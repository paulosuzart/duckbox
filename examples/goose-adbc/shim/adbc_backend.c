/* ADBC Flight SQL backend for the goose dbx_* API.
 *
 * Goose cannot carry AdbcDatabase / ArrowArrayStream across extern fn
 * (private_data + callbacks). This file keeps those objects behind integer
 * handles and materializes each result as a flat table of cells.
 *
 * A later direct-core backend can implement the same symbols.
 */
#include "goose.h"

#include <arrow-adbc/adbc.h>
#include <arrow-adbc/adbc_driver_manager.h>

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#define dbx_access _access
#define DBX_R_OK 4
#else
#include <unistd.h>
#define dbx_access access
#define DBX_R_OK R_OK
#endif

typedef struct {
    uint8_t *data;
    int64_t len;
} sl_u8;

#define DBX_MAX_CONN 8
#define DBX_MAX_RESULT 8
#define DBX_ERR_LEN 1024

enum {
    DBX_KIND_NULL = 0,
    DBX_KIND_I64 = 1,
    DBX_KIND_F64 = 2,
    DBX_KIND_TEXT = 3,
    DBX_KIND_BOOL = 4,
    DBX_KIND_OTHER = 5
};

typedef struct {
    int kind;
    int64_t i;
    double f;
    char *text;
} DbCell;

typedef struct {
    int used;
    struct AdbcDatabase database;
    struct AdbcConnection connection;
} DbConn;

typedef struct {
    int used;
    int64_t nrows;
    int64_t ncols;
    char **colnames;
    DbCell *cells;
} DbResult;

static DbConn g_conns[DBX_MAX_CONN + 1];
static DbResult g_results[DBX_MAX_RESULT + 1];
static char g_err[DBX_ERR_LEN];

static void set_err(const char *msg) {
    if (!msg) {
        msg = "unknown error";
    }
    snprintf(g_err, sizeof g_err, "%s", msg);
}

static void set_adbc_err(const char *what, struct AdbcError *error) {
    if (error && error->message && error->message[0]) {
        snprintf(g_err, sizeof g_err, "%s: %s", what, error->message);
    } else {
        snprintf(g_err, sizeof g_err, "%s", what);
    }
    if (error && error->release) {
        error->release(error);
        memset(error, 0, sizeof *error);
    }
}

static char *dup_slice(sl_u8 s) {
    char *z = (char *)malloc((size_t)s.len + 1);
    if (!z) {
        return NULL;
    }
    if (s.len > 0 && s.data) {
        memcpy(z, s.data, (size_t)s.len);
    }
    z[s.len] = 0;
    return z;
}

static char *dup_cstr(const char *s) {
    if (!s) {
        s = "";
    }
    size_t n = strlen(s);
    char *z = (char *)malloc(n + 1);
    if (!z) {
        return NULL;
    }
    memcpy(z, s, n + 1);
    return z;
}

static void append_bytes(gs_rref out, const void *p, size_t n) {
    if (n == 0) {
        return;
    }
    gs_bld_append(out, p, (int64_t)n);
}

static void append_cstr(gs_rref out, const char *s) {
    if (s && s[0]) {
        append_bytes(out, s, strlen(s));
    }
}

static int find_flightsql(char *out, size_t n) {
    const char *env = getenv("DBX_ADBC_FLIGHTSQL");
    if (env && env[0] && dbx_access(env, DBX_R_OK) == 0) {
        snprintf(out, n, "%s", env);
        return 0;
    }

    char self[4096];
    ssize_t m = -1;
#ifdef __linux__
    m = readlink("/proc/self/exe", self, sizeof self - 1);
#endif
    if (m > 0) {
        self[m] = 0;
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = 0;
        }
        snprintf(out, n, "%s/.deps/adbc/lib/libadbc_driver_flightsql.so", self);
        if (dbx_access(out, DBX_R_OK) == 0) {
            return 0;
        }
        snprintf(out, n, "%s/libadbc_driver_flightsql.so", self);
        if (dbx_access(out, DBX_R_OK) == 0) {
            return 0;
        }
#ifdef __APPLE__
        snprintf(out, n, "%s/.deps/adbc/lib/libadbc_driver_flightsql.dylib", self);
        if (dbx_access(out, DBX_R_OK) == 0) {
            return 0;
        }
#endif
    }

    const char *fallback =
#ifdef __APPLE__
        "libadbc_driver_flightsql.dylib";
#else
        "libadbc_driver_flightsql.so";
#endif
    snprintf(out, n, "%s", fallback);
    return 0;
}

static void free_result_body(DbResult *r) {
    if (!r) {
        return;
    }
    if (r->colnames) {
        for (int64_t c = 0; c < r->ncols; c++) {
            free(r->colnames[c]);
        }
        free(r->colnames);
    }
    if (r->cells) {
        int64_t n = r->nrows * r->ncols;
        for (int64_t i = 0; i < n; i++) {
            free(r->cells[i].text);
        }
        free(r->cells);
    }
    r->colnames = NULL;
    r->cells = NULL;
    r->nrows = 0;
    r->ncols = 0;
}

static void close_conn_body(DbConn *c) {
    struct AdbcError error;
    memset(&error, 0, sizeof error);
    if (c->connection.private_data) {
        AdbcConnectionRelease(&c->connection, &error);
        if (error.release) {
            error.release(&error);
        }
        memset(&c->connection, 0, sizeof c->connection);
    }
    memset(&error, 0, sizeof error);
    if (c->database.private_data) {
        AdbcDatabaseRelease(&c->database, &error);
        if (error.release) {
            error.release(&error);
        }
        memset(&c->database, 0, sizeof c->database);
    }
}

static DbConn *conn_of(int64_t h) {
    if (h < 1 || h > DBX_MAX_CONN || !g_conns[h].used) {
        set_err("invalid connection handle");
        return NULL;
    }
    return &g_conns[h];
}

static DbResult *result_of(int64_t h) {
    if (h < 1 || h > DBX_MAX_RESULT || !g_results[h].used) {
        set_err("invalid result handle");
        return NULL;
    }
    return &g_results[h];
}

static uint8_t load_u8(const uint8_t *p) {
    uint8_t v;
    memcpy(&v, p, 1);
    return v;
}

static int16_t load_i16(const uint8_t *p) {
    int16_t v;
    memcpy(&v, p, 2);
    return v;
}

static int32_t load_i32(const uint8_t *p) {
    int32_t v;
    memcpy(&v, p, 4);
    return v;
}

static int64_t load_i64(const uint8_t *p) {
    int64_t v;
    memcpy(&v, p, 8);
    return v;
}

static uint16_t load_u16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t load_u32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t load_u64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static float load_f32(const uint8_t *p) {
    float v;
    memcpy(&v, p, 4);
    return v;
}

static double load_f64(const uint8_t *p) {
    double v;
    memcpy(&v, p, 8);
    return v;
}

static int bit_is_set(const uint8_t *bitmap, int64_t i) {
    return (bitmap[i / 8] >> (i % 8)) & 1;
}

static int is_valid(const struct ArrowArray *arr, int64_t i) {
    if (!arr->buffers || arr->n_buffers < 1 || !arr->buffers[0]) {
        return 1;
    }
    return bit_is_set((const uint8_t *)arr->buffers[0], arr->offset + i);
}

static const char *col_format(const struct ArrowSchema *schema, int64_t col) {
    if (!schema || col < 0 || col >= schema->n_children || !schema->children ||
        !schema->children[col] || !schema->children[col]->format) {
        return "";
    }
    return schema->children[col]->format;
}

static const char *col_name_of(const struct ArrowSchema *schema, int64_t col) {
    if (!schema || col < 0 || col >= schema->n_children || !schema->children ||
        !schema->children[col] || !schema->children[col]->name) {
        return "";
    }
    return schema->children[col]->name;
}

static void decode_cell(DbCell *cell, const char *fmt, const struct ArrowArray *arr,
                        int64_t row) {
    memset(cell, 0, sizeof *cell);
    if (!fmt || !arr || !is_valid(arr, row)) {
        cell->kind = DBX_KIND_NULL;
        return;
    }
    int64_t i = arr->offset + row;
    const uint8_t *values = NULL;
    if (arr->buffers && arr->n_buffers >= 2) {
        values = (const uint8_t *)arr->buffers[1];
    }

    if (strcmp(fmt, "n") == 0) {
        cell->kind = DBX_KIND_NULL;
        return;
    }
    if (strcmp(fmt, "b") == 0) {
        cell->kind = DBX_KIND_BOOL;
        if (arr->buffers && arr->n_buffers >= 2 && arr->buffers[1]) {
            cell->i = bit_is_set((const uint8_t *)arr->buffers[1], i) ? 1 : 0;
        }
        return;
    }
    if (strcmp(fmt, "c") == 0 && values) {
        cell->kind = DBX_KIND_I64;
        cell->i = (int8_t)load_u8(values + i);
        return;
    }
    if (strcmp(fmt, "C") == 0 && values) {
        cell->kind = DBX_KIND_I64;
        cell->i = load_u8(values + i);
        return;
    }
    if (strcmp(fmt, "s") == 0 && values) {
        cell->kind = DBX_KIND_I64;
        cell->i = load_i16(values + (size_t)i * 2);
        return;
    }
    if (strcmp(fmt, "S") == 0 && values) {
        cell->kind = DBX_KIND_I64;
        cell->i = load_u16(values + (size_t)i * 2);
        return;
    }
    if ((strcmp(fmt, "i") == 0 || strcmp(fmt, "tdD") == 0 || strcmp(fmt, "tdm") == 0) &&
        values) {
        cell->kind = DBX_KIND_I64;
        cell->i = load_i32(values + (size_t)i * 4);
        return;
    }
    if (strcmp(fmt, "I") == 0 && values) {
        cell->kind = DBX_KIND_I64;
        cell->i = load_u32(values + (size_t)i * 4);
        return;
    }
    if ((fmt[0] == 'l' && fmt[1] == 0) ||
        (fmt[0] == 't' && (fmt[1] == 's' || fmt[1] == 'i'))) {
        if (values) {
            cell->kind = DBX_KIND_I64;
            cell->i = load_i64(values + (size_t)i * 8);
        }
        return;
    }
    if (strcmp(fmt, "L") == 0 && values) {
        cell->kind = DBX_KIND_I64;
        cell->i = (int64_t)load_u64(values + (size_t)i * 8);
        return;
    }
    if (strcmp(fmt, "f") == 0 && values) {
        cell->kind = DBX_KIND_F64;
        cell->f = load_f32(values + (size_t)i * 4);
        return;
    }
    if (strcmp(fmt, "g") == 0 && values) {
        cell->kind = DBX_KIND_F64;
        cell->f = load_f64(values + (size_t)i * 8);
        return;
    }
    if ((strcmp(fmt, "u") == 0 || strcmp(fmt, "z") == 0) && arr->n_buffers >= 3 &&
        arr->buffers[1] && arr->buffers[2]) {
        const uint8_t *offb = (const uint8_t *)arr->buffers[1];
        const uint8_t *data = (const uint8_t *)arr->buffers[2];
        int32_t start = load_i32(offb + (size_t)i * 4);
        int32_t end = load_i32(offb + (size_t)(i + 1) * 4);
        int32_t n = end - start;
        if (n < 0) {
            n = 0;
        }
        cell->kind = DBX_KIND_TEXT;
        cell->text = (char *)malloc((size_t)n + 1);
        if (cell->text) {
            if (n > 0) {
                memcpy(cell->text, data + start, (size_t)n);
            }
            cell->text[n] = 0;
        }
        return;
    }
    if ((strcmp(fmt, "U") == 0 || strcmp(fmt, "Z") == 0) && arr->n_buffers >= 3 &&
        arr->buffers[1] && arr->buffers[2]) {
        const uint8_t *offb = (const uint8_t *)arr->buffers[1];
        const uint8_t *data = (const uint8_t *)arr->buffers[2];
        int64_t start = load_i64(offb + (size_t)i * 8);
        int64_t end = load_i64(offb + (size_t)(i + 1) * 8);
        int64_t n = end - start;
        if (n < 0) {
            n = 0;
        }
        cell->kind = DBX_KIND_TEXT;
        cell->text = (char *)malloc((size_t)n + 1);
        if (cell->text) {
            if (n > 0) {
                memcpy(cell->text, data + start, (size_t)n);
            }
            cell->text[n] = 0;
        }
        return;
    }

    cell->kind = DBX_KIND_OTHER;
    char buf[64];
    snprintf(buf, sizeof buf, "<%s>", fmt);
    cell->text = dup_cstr(buf);
}

static int grow_cells(DbResult *r, int64_t add_rows) {
    int64_t new_rows = r->nrows + add_rows;
    DbCell *next = (DbCell *)realloc(r->cells, (size_t)new_rows * (size_t)r->ncols * sizeof(DbCell));
    if (!next) {
        set_err("out of memory growing result");
        return -1;
    }
    r->cells = next;
    memset(r->cells + r->nrows * r->ncols, 0, (size_t)add_rows * (size_t)r->ncols * sizeof(DbCell));
    return 0;
}

static int ingest_batch(DbResult *r, const struct ArrowSchema *schema, struct ArrowArray *batch) {
    if (!batch || batch->length <= 0) {
        return 0;
    }
    if (batch->n_children != r->ncols) {
        set_err("Arrow batch column count changed mid-stream");
        return -1;
    }
    if (grow_cells(r, batch->length) != 0) {
        return -1;
    }
    for (int64_t row = 0; row < batch->length; row++) {
        for (int64_t col = 0; col < r->ncols; col++) {
            const struct ArrowArray *arr =
                (batch->children && batch->children[col]) ? batch->children[col] : NULL;
            decode_cell(&r->cells[(r->nrows + row) * r->ncols + col], col_format(schema, col),
                        arr, row);
        }
    }
    r->nrows += batch->length;
    return 0;
}

static int64_t alloc_conn(void) {
    for (int64_t i = 1; i <= DBX_MAX_CONN; i++) {
        if (!g_conns[i].used) {
            memset(&g_conns[i], 0, sizeof g_conns[i]);
            g_conns[i].used = 1;
            return i;
        }
    }
    set_err("too many open connections");
    return 0;
}

static int64_t alloc_result(void) {
    for (int64_t i = 1; i <= DBX_MAX_RESULT; i++) {
        if (!g_results[i].used) {
            memset(&g_results[i], 0, sizeof g_results[i]);
            g_results[i].used = 1;
            return i;
        }
    }
    set_err("too many open results");
    return 0;
}

int64_t dbx_connect(sl_u8 url, sl_u8 sandbox, sl_u8 key) {
    g_err[0] = 0;
    char *url_z = dup_slice(url);
    char *sandbox_z = dup_slice(sandbox);
    char *key_z = dup_slice(key);
    if (!url_z || !sandbox_z || !key_z) {
        free(url_z);
        free(sandbox_z);
        free(key_z);
        set_err("out of memory");
        return 0;
    }

    char driver[4096];
    find_flightsql(driver, sizeof driver);

    int64_t h = alloc_conn();
    if (h == 0) {
        free(url_z);
        free(sandbox_z);
        free(key_z);
        return 0;
    }
    DbConn *c = &g_conns[h];
    struct AdbcError error;
    memset(&error, 0, sizeof error);

    AdbcStatusCode st = AdbcDatabaseNew(&c->database, &error);
    if (st == ADBC_STATUS_OK) {
        st = AdbcDatabaseSetOption(&c->database, "driver", driver, &error);
    }
    if (st == ADBC_STATUS_OK) {
        st = AdbcDatabaseSetOption(&c->database, ADBC_OPTION_URI, url_z, &error);
    }
    /* Flight SQL driver docs: adbc.flight.sql.rpc.call_header.<lowercase-name>
       on Database, Connection, or Statement. Header names must be lowercase. */
    if (st == ADBC_STATUS_OK) {
        st = AdbcDatabaseSetOption(&c->database,
                                   "adbc.flight.sql.rpc.call_header.x-duckbox-sandbox",
                                   sandbox_z, &error);
    }
    if (st == ADBC_STATUS_OK) {
        st = AdbcDatabaseSetOption(&c->database, "adbc.flight.sql.rpc.call_header.x-duckbox-caller",
                                   "local", &error);
    }
    if (st == ADBC_STATUS_OK && key_z[0]) {
        st = AdbcDatabaseSetOption(&c->database, "adbc.flight.sql.rpc.call_header.x-duckbox-key",
                                   key_z, &error);
    }
    if (st == ADBC_STATUS_OK) {
        st = AdbcDatabaseInit(&c->database, &error);
    }
    if (st == ADBC_STATUS_OK) {
        st = AdbcConnectionNew(&c->connection, &error);
    }
    if (st == ADBC_STATUS_OK) {
        st = AdbcConnectionInit(&c->connection, &c->database, &error);
    }

    free(url_z);
    free(sandbox_z);
    free(key_z);

    if (st != ADBC_STATUS_OK) {
        set_adbc_err("connect", &error);
        close_conn_body(c);
        c->used = 0;
        return 0;
    }
    return h;
}

void dbx_close(int64_t h) {
    DbConn *c = conn_of(h);
    if (!c) {
        return;
    }
    close_conn_body(c);
    c->used = 0;
}

int64_t dbx_query(int64_t h, sl_u8 sql) {
    g_err[0] = 0;
    DbConn *c = conn_of(h);
    if (!c) {
        return 0;
    }
    char *sql_z = dup_slice(sql);
    if (!sql_z) {
        set_err("out of memory");
        return 0;
    }

    int64_t rh = alloc_result();
    if (rh == 0) {
        free(sql_z);
        return 0;
    }
    DbResult *r = &g_results[rh];

    struct AdbcError error;
    memset(&error, 0, sizeof error);
    struct AdbcStatement statement;
    memset(&statement, 0, sizeof statement);
    struct ArrowArrayStream stream;
    memset(&stream, 0, sizeof stream);
    struct ArrowSchema schema;
    memset(&schema, 0, sizeof schema);

    AdbcStatusCode st = AdbcStatementNew(&c->connection, &statement, &error);
    if (st == ADBC_STATUS_OK) {
        st = AdbcStatementSetSqlQuery(&statement, sql_z, &error);
    }
    int64_t rows_affected = -1;
    if (st == ADBC_STATUS_OK) {
        st = AdbcStatementExecuteQuery(&statement, &stream, &rows_affected, &error);
    }
    free(sql_z);
    if (st != ADBC_STATUS_OK) {
        set_adbc_err("query", &error);
        if (statement.private_data) {
            AdbcStatementRelease(&statement, &error);
            if (error.release) {
                error.release(&error);
            }
        }
        r->used = 0;
        return 0;
    }

    int rc = 0;
    if (stream.get_schema) {
        rc = stream.get_schema(&stream, &schema);
    }
    if (rc != 0) {
        set_err(stream.get_last_error ? stream.get_last_error(&stream)
                                      : "Arrow stream get_schema failed");
        if (stream.release) {
            stream.release(&stream);
        }
        AdbcStatementRelease(&statement, &error);
        if (error.release) {
            error.release(&error);
        }
        r->used = 0;
        return 0;
    }

    r->ncols = schema.n_children;
    if (r->ncols < 0) {
        r->ncols = 0;
    }
    if (r->ncols > 0) {
        r->colnames = (char **)calloc((size_t)r->ncols, sizeof(char *));
        if (!r->colnames) {
            set_err("out of memory");
            if (schema.release) {
                schema.release(&schema);
            }
            if (stream.release) {
                stream.release(&stream);
            }
            AdbcStatementRelease(&statement, &error);
            if (error.release) {
                error.release(&error);
            }
            free_result_body(r);
            r->used = 0;
            return 0;
        }
        for (int64_t col = 0; col < r->ncols; col++) {
            r->colnames[col] = dup_cstr(col_name_of(&schema, col));
        }
    }

    int ok = 1;
    if (stream.get_next) {
        for (;;) {
            struct ArrowArray batch;
            memset(&batch, 0, sizeof batch);
            rc = stream.get_next(&stream, &batch);
            if (rc != 0) {
                set_err(stream.get_last_error ? stream.get_last_error(&stream)
                                              : "Arrow stream get_next failed");
                ok = 0;
                break;
            }
            if (!batch.release) {
                break;
            }
            if (ingest_batch(r, &schema, &batch) != 0) {
                ok = 0;
                if (batch.release) {
                    batch.release(&batch);
                }
                break;
            }
            if (batch.release) {
                batch.release(&batch);
            }
        }
    }

    if (schema.release) {
        schema.release(&schema);
    }
    if (stream.release) {
        stream.release(&stream);
    }
    AdbcStatementRelease(&statement, &error);
    if (error.release) {
        error.release(&error);
    }

    if (!ok) {
        free_result_body(r);
        r->used = 0;
        return 0;
    }
    return rh;
}

void dbx_result_free(int64_t h) {
    DbResult *r = result_of(h);
    if (!r) {
        return;
    }
    free_result_body(r);
    r->used = 0;
}

int64_t dbx_result_nrows(int64_t h) {
    DbResult *r = result_of(h);
    return r ? r->nrows : 0;
}

int64_t dbx_result_ncols(int64_t h) {
    DbResult *r = result_of(h);
    return r ? r->ncols : 0;
}

static DbCell *cell_at(int64_t h, int64_t row, int64_t col) {
    DbResult *r = result_of(h);
    if (!r) {
        return NULL;
    }
    if (row < 0 || col < 0 || row >= r->nrows || col >= r->ncols) {
        set_err("cell out of range");
        return NULL;
    }
    return &r->cells[row * r->ncols + col];
}

int32_t dbx_result_col_name(int64_t h, int64_t col, gs_rref out) {
    DbResult *r = result_of(h);
    if (!r) {
        return 1;
    }
    if (col < 0 || col >= r->ncols || !r->colnames) {
        set_err("column out of range");
        return 1;
    }
    append_cstr(out, r->colnames[col]);
    return 0;
}

int32_t dbx_result_cell_kind(int64_t h, int64_t row, int64_t col) {
    DbCell *cell = cell_at(h, row, col);
    return cell ? (int32_t)cell->kind : DBX_KIND_NULL;
}

int64_t dbx_result_cell_i64(int64_t h, int64_t row, int64_t col) {
    DbCell *cell = cell_at(h, row, col);
    return cell ? cell->i : 0;
}

double dbx_result_cell_f64(int64_t h, int64_t row, int64_t col) {
    DbCell *cell = cell_at(h, row, col);
    return cell ? cell->f : 0.0;
}

int32_t dbx_result_cell_text(int64_t h, int64_t row, int64_t col, gs_rref out) {
    DbCell *cell = cell_at(h, row, col);
    if (!cell) {
        return 1;
    }
    if (cell->text) {
        append_cstr(out, cell->text);
    }
    return 0;
}

void dbx_last_error(gs_rref out) { append_cstr(out, g_err); }
