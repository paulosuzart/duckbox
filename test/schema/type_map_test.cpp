#include "check.hpp"
#include "suite.hpp"

#include "sandbox/arrow_ipc.hpp"
#include "sandbox/arrow_types.hpp"
#include "sandbox/sandbox.hpp"

#include <arrow/type.h>
#include <arrow/type_fwd.h>

#include <string>
#include <utility>
#include <vector>

namespace {

void ExpectTypeId(const std::string &logical, arrow::Type::type want, const std::string &msg) {
    try {
        auto lt = duckbox::LogicalTypeFromName(logical);
        auto got = duckbox::MapTypeName(logical);
        duckbox::test::Expect(got && got->id() == want,
                              msg + " (got " + (got ? got->ToString() : "null") +
                                  " logical_id=" + std::to_string(static_cast<int>(lt.id())) + ")");
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, msg + " threw " + e.what());
    }
}

void ExpectEnumValues(const std::string &logical, const std::vector<std::string> &want,
                      const std::string &msg) {
    try {
        auto lt = duckbox::LogicalTypeFromName(logical);
        duckbox::test::Expect(lt.id() == duckbox::ddb::LogicalTypeId::ENUM, msg + " is ENUM");
        duckbox::test::Expect(duckbox::ddb::EnumType::GetSize(lt) == want.size(),
                              msg + " enum size " +
                                  std::to_string(duckbox::ddb::EnumType::GetSize(lt)));
        for (duckbox::ddb::idx_t i = 0; i < want.size(); i++) {
            auto got = duckbox::ddb::EnumType::GetString(lt, i).GetString();
            duckbox::test::Expect(got == want[i], msg + " value[" + std::to_string(i) + "]=" + got);
        }
        auto mapped = duckbox::MapTypeName(logical);
        duckbox::test::Expect(mapped && mapped->id() == arrow::Type::DICTIONARY,
                              msg + " maps to dictionary");
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, msg + " threw " + e.what());
    }
}

void ExpectInvalidTypeName(const std::string &logical, const std::string &msg) {
    try {
        (void)duckbox::LogicalTypeFromName(logical);
        duckbox::test::Expect(false, msg + " (no throw)");
    } catch (const std::exception &e) {
        duckbox::test::Expect(std::string(e.what()) == "invalid logical type name",
                              msg + " threw '" + std::string(e.what()) + "'");
    }
}

void ExpectSchemaMatch(const std::shared_ptr<arrow::Schema> &advertised,
                       const std::vector<uint8_t> &ipc, const std::string &msg) {
    auto batch = duckbox::SchemaFromArrowIpc(ipc);
    duckbox::test::Expect(advertised && batch && advertised->Equals(*batch),
                          msg + " advertised=" + (advertised ? advertised->ToString() : "null") +
                              " batch=" + (batch ? batch->ToString() : "null"));
}

} // namespace

void duckbox::test::RunArrowTypeMapTests() {
    using namespace duckbox;

    ExpectTypeId("TINYINT", arrow::Type::INT8, "TINYINT is int8");
    ExpectTypeId("SMALLINT", arrow::Type::INT16, "SMALLINT is int16");
    ExpectTypeId("INTEGER", arrow::Type::INT32, "INTEGER is int32");
    ExpectTypeId("INT", arrow::Type::INT32, "INT is int32");
    ExpectTypeId("BIGINT", arrow::Type::INT64, "BIGINT is int64, not int32");
    ExpectTypeId("HUGEINT", arrow::Type::DECIMAL128, "HUGEINT is decimal128");
    ExpectTypeId("UBIGINT", arrow::Type::UINT64, "UBIGINT is uint64");
    ExpectTypeId("UHUGEINT", arrow::Type::DECIMAL128, "UHUGEINT is decimal128");
    ExpectTypeId("UTINYINT", arrow::Type::UINT8, "UTINYINT is uint8");
    ExpectTypeId("USMALLINT", arrow::Type::UINT16, "USMALLINT is uint16");
    ExpectTypeId("UINTEGER", arrow::Type::UINT32, "UINTEGER is uint32");
    ExpectTypeId("FLOAT", arrow::Type::FLOAT, "FLOAT is float32");
    ExpectTypeId("DOUBLE", arrow::Type::DOUBLE, "DOUBLE is float64");
    ExpectTypeId("DECIMAL(10,2)", arrow::Type::DECIMAL128, "DECIMAL(10,2) is decimal128");
    ExpectTypeId("BOOLEAN", arrow::Type::BOOL, "BOOLEAN is bool");
    ExpectTypeId("BOOL", arrow::Type::BOOL, "BOOL is bool");
    ExpectTypeId("VARCHAR", arrow::Type::STRING, "VARCHAR is utf8");
    ExpectTypeId("BLOB", arrow::Type::BINARY, "BLOB is binary");
    ExpectTypeId("DATE", arrow::Type::DATE32, "DATE is date32");
    ExpectTypeId("TIMESTAMP", arrow::Type::TIMESTAMP, "TIMESTAMP is timestamp");
    ExpectTypeId("INTERVAL", arrow::Type::INTERVAL_MONTH_DAY_NANO, "INTERVAL is not int32");
    ExpectTypeId("INTEGER[]", arrow::Type::LIST, "INTEGER[] is list, not varchar");
    ExpectTypeId("STRUCT(a INTEGER, b INTEGER)", arrow::Type::STRUCT,
                 "STRUCT(...) is struct, not varchar");
    ExpectTypeId("MAP(VARCHAR, INTEGER)", arrow::Type::MAP, "MAP(...) is map, not varchar");
    ExpectTypeId("DOUBLE PRECISION", arrow::Type::DOUBLE, "DOUBLE PRECISION is float64");
    ExpectTypeId("DECIMAL(10, 2)", arrow::Type::DECIMAL128, "DECIMAL(10, 2) keeps the space");
    ExpectTypeId("NUMERIC(10,2)", arrow::Type::DECIMAL128, "NUMERIC(10,2) is decimal128");
    ExpectTypeId("VARCHAR(10)", arrow::Type::STRING, "VARCHAR(10) is utf8");
    ExpectTypeId("STRUCT(\"A\" INTEGER)", arrow::Type::STRUCT, "STRUCT(\"A\" INTEGER) is struct");
    ExpectEnumValues("ENUM('a--b', 'c')", {"a--b", "c"}, "ENUM('a--b') keeps -- inside quotes");
    ExpectEnumValues("ENUM('x/*y', 'z')", {"x/*y", "z"}, "ENUM('x/*y') keeps /* inside quotes");
    ExpectEnumValues("ENUM('p$$q', 'r')", {"p$$q", "r"}, "ENUM('p$$q') keeps $$ inside quotes");
    ExpectEnumValues("ENUM('a;b', 'c')", {"a;b", "c"}, "ENUM('a;b') keeps ; inside quotes");
    ExpectEnumValues("ENUM('a''--b', 'c')", {"a'--b", "c"},
                     "ENUM doubled single-quote escape is accepted");
    ExpectTypeId("STRUCT(\"a--b\" INTEGER)", arrow::Type::STRUCT,
                 "STRUCT(\"a--b\" INTEGER) keeps -- inside quotes");
    ExpectTypeId("STRUCT(\"c;d\" INTEGER)", arrow::Type::STRUCT,
                 "STRUCT(\"c;d\" INTEGER) keeps ; inside quotes");
    ExpectTypeId("STRUCT(\"x/*y\" INTEGER)", arrow::Type::STRUCT,
                 "STRUCT(\"x/*y\" INTEGER) keeps /* inside quotes");
    ExpectTypeId("STRUCT(\"p$$q\" INTEGER)", arrow::Type::STRUCT,
                 "STRUCT(\"p$$q\" INTEGER) keeps $$ inside quotes");
    ExpectTypeId("STRUCT(\"a\"\"--b\" INTEGER)", arrow::Type::STRUCT,
                 "STRUCT doubled double-quote escape is accepted");
    ExpectEnumValues("ENUM(E'a--b', 'c')", {"a--b", "c"},
                     "ENUM(E'a--b') keeps -- inside an E-string");
    ExpectEnumValues("ENUM(e'x/*y', 'z')", {"x/*y", "z"}, "ENUM lowercase e-string may contain /*");
    ExpectEnumValues("ENUM(E'a\\'--b', 'c')", {"a'--b", "c"},
                     "ENUM E-string backslash-escaped quote is accepted");
    ExpectEnumValues("ENUM($t$a--b$t$, 'c')", {"a--b", "c"},
                     "ENUM dollar-quoted value may contain --");
    ExpectEnumValues("ENUM($$x/*y$$, 'z')", {"x/*y", "z"},
                     "ENUM empty-tag dollar quote may contain /*");
    ExpectEnumValues("ENUM($ç$ok$ç$)", {"ok"}, "ENUM unicode dollar-quote tag is accepted");
    ExpectTypeId("STRUCT(x$t$ /* */ INTEGER, y$t$ VARCHAR)", arrow::Type::STRUCT,
                 "STRUCT x$t$ /* */ keeps $ in the identifier and a closed comment");
    {
        auto st = LogicalTypeFromName("STRUCT(x$t$ /* hidden */ INTEGER, y$t$ VARCHAR)");
        Expect(st.id() == ddb::LogicalTypeId::STRUCT && ddb::StructType::GetChildCount(st) == 2 &&
                   ddb::StructType::GetChildName(st, 0) == "x$t$" &&
                   ddb::StructType::GetChildName(st, 1) == "y$t$",
               "closed comment does not rename STRUCT x$t$ / y$t$ fields");
    }
    ExpectInvalidTypeName("ENUM(E'x\\'')) -- '", "E-string leftover ) -- is rejected");
    ExpectInvalidTypeName("ENUM($t$'$t$)) -- '", "dollar-quote leftover ) -- is rejected");
    ExpectInvalidTypeName("ENUM(E'unclosed", "unclosed E-string type name is rejected");
    ExpectInvalidTypeName("ENUM($t$unclosed", "unclosed dollar-quote type name is rejected");
    ExpectInvalidTypeName("ENUM($1$)", "$1$ is a parameter, not a dollar-quote tag");
    ExpectInvalidTypeName("ENUM(NOE'x')", "E' only starts an E-string at a token boundary");

    Expect(LogicalTypeFromName("DOUBLE PRECISION") == LogicalTypeFromName("DOUBLE"),
           "DOUBLE PRECISION equals DOUBLE");
    Expect(LogicalTypeFromName("DECIMAL(10, 2)") == LogicalTypeFromName("DECIMAL(10,2)"),
           "DECIMAL(10, 2) equals DECIMAL(10,2)");
    Expect(LogicalTypeFromName("NUMERIC(10,2)") == LogicalTypeFromName("DECIMAL(10,2)"),
           "NUMERIC(10,2) equals DECIMAL(10,2)");

    auto dec_space = MapTypeName("DECIMAL(10, 2)");
    Expect(dec_space && dec_space->id() == arrow::Type::DECIMAL128,
           "DECIMAL(10, 2) maps to decimal128");
    if (dec_space && dec_space->id() == arrow::Type::DECIMAL128) {
        auto *d = static_cast<arrow::Decimal128Type *>(dec_space.get());
        Expect(d->precision() == 10 && d->scale() == 2, "DECIMAL(10, 2) keeps precision and scale");
    }
    auto numeric = MapTypeName("NUMERIC(10,2)");
    Expect(numeric && numeric->Equals(*dec_space), "NUMERIC(10,2) matches DECIMAL(10, 2)");

    auto dec = MapTypeName("DECIMAL(10,2)");
    Expect(dec && dec->id() == arrow::Type::DECIMAL128, "DECIMAL maps to decimal128");
    if (dec && dec->id() == arrow::Type::DECIMAL128) {
        auto *d = static_cast<arrow::Decimal128Type *>(dec.get());
        Expect(d->precision() == 10 && d->scale() == 2, "DECIMAL(10,2) keeps precision and scale");
    }

    auto bigint = MapTypeName("BIGINT");
    Expect(bigint && !bigint->Equals(*arrow::int32()), "BIGINT must not collapse to int32");

    ExpectInvalidTypeName("INTEGER; CREATE TABLE pwned(i INT)",
                          "injection-style type name is rejected");
    try {
        (void)MapTypeName("INTEGER; CREATE TABLE pwned(i INT)");
        Expect(false, "MapTypeName stacked statements (no throw)");
    } catch (const std::exception &e) {
        Expect(std::string(e.what()) == "invalid logical type name",
               "MapTypeName rejects stacked statements with the exact message");
    }
    ExpectInvalidTypeName(std::string("INTEGER") + '\n', "newline in a type name is rejected");
    ExpectInvalidTypeName(std::string("INTEGER") + '\t', "tab in a type name is rejected");
    ExpectInvalidTypeName("INTEGER leftover", "trailing garbage after a type name is rejected");
    ExpectInvalidTypeName("INTEGER[] extra",
                          "trailing garbage after a nested type name is rejected");
    ExpectInvalidTypeName("NOTATYPE", "unknown type name is not VARCHAR");
    ExpectInvalidTypeName("INTEGER--x", "SQL comment in a type name is rejected");
    ExpectInvalidTypeName("INTEGER -- comment", "spaced SQL comment in a type name is rejected");
    ExpectInvalidTypeName("INTEGER) OR (1=1", "CAST leftover OR-injection is rejected");
    ExpectInvalidTypeName("INTEGER), 1", "extra expression after a type name is rejected");
    ExpectTypeId("INTEGER/*x*/", arrow::Type::INT32, "closed comment does not change INTEGER");
    ExpectInvalidTypeName("INTEGER$$x", "dollar-quote in a type name is rejected");
    ExpectInvalidTypeName("ANY", "ANY is not a concrete column type");
    ExpectInvalidTypeName("UNKNOWN", "UNKNOWN is not a concrete column type");
    ExpectInvalidTypeName("   ", "whitespace-only type name is rejected");
    ExpectInvalidTypeName("INTEGER /*", "unclosed block comment is rejected");
    ExpectInvalidTypeName("INTEGER /* )", "comment hiding ) is rejected");
    ExpectInvalidTypeName("memory.main.INTEGER",
                          "catalog-qualified type name uses the exact invalid message");
    ExpectInvalidTypeName(std::string(64 * 1024 + 1, 'X'),
                          "type names longer than 64 KiB are rejected");
    {
        std::string big = "ENUM(";
        std::vector<std::string> labels;
        labels.reserve(256);
        for (int i = 0; i < 256; i++) {
            if (i) {
                big += ", ";
            }
            auto lab = "v" + std::to_string(i);
            big += "'" + lab + "'";
            labels.push_back(lab);
        }
        big += ")";
        Expect(big.size() <= 64 * 1024, "large ENUM fixture stays under the 64 KiB cap");
        ExpectEnumValues(big, labels, "large ENUM under 64 KiB is accepted");
    }
    ExpectTypeId("INTEGER  ", arrow::Type::INT32, "trailing spaces are trimmed");

    {
        std::vector<ColumnSchema> cols{
            {"count_star()", "BIGINT"}, {"h", "HUGEINT"}, {"u", "UBIGINT"}};
        auto schema = SchemaFromCols(cols);
        Expect(schema && schema->num_fields() == 3, "SchemaFromCols keeps three integer widths");
        Expect(schema->field(0)->type()->id() == arrow::Type::INT64,
               "count(*) type name BIGINT → int64");
        Expect(schema->field(1)->type()->id() == arrow::Type::DECIMAL128,
               "HUGEINT column stays 128-bit");
        Expect(schema->field(2)->type()->id() == arrow::Type::UINT64,
               "UBIGINT column stays uint64");
    }

    {
        auto daemon = TestDaemon();
        auto policy = TestPolicy();
        auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
        TenantSandbox box(daemon, policy, key, MemorySpecDir());

        const std::vector<std::pair<std::string, std::string>> queries = {
            {"SELECT count(*) FROM deals", "count(*)"},
            {"SELECT CAST(id AS BIGINT) AS id64 FROM deals", "BIGINT"},
            {"SELECT CAST(id AS HUGEINT) AS idh FROM deals", "HUGEINT"},
            {"SELECT CAST(id AS UBIGINT) AS idu FROM deals", "UBIGINT"},
            {"SELECT SUM(CAST(amount AS BIGINT)) AS s FROM deals", "SUM(BIGINT)"},
            {"SELECT CAST(amount AS FLOAT) AS f, CAST(amount AS DOUBLE) AS d FROM deals",
             "FLOAT/DOUBLE"},
            {"SELECT CAST('2020-01-01' AS DATE) AS dt FROM deals", "DATE"},
        };

        for (auto &q : queries) {
            auto advertised = box.DescribeRewrittenArrow(q.first);
            auto names = box.DescribeRewritten(q.first);
            Expect(!names.empty() && advertised &&
                       advertised->num_fields() == static_cast<int>(names.size()),
                   q.second + " describe returns fields");
            auto out = box.Execute(q.first);
            Expect(!out.arrow_ipc.empty(), q.second + " produced batches");
            ExpectSchemaMatch(advertised, out.arrow_ipc,
                              q.second + " describe matches Execute IPC");
            auto from_names = SchemaFromCols(names);
            ExpectSchemaMatch(from_names, out.arrow_ipc,
                              q.second + " type-name mapping matches Execute IPC");
        }

        auto count_cols = box.DescribeRewritten("SELECT count(*) FROM deals");
        Expect(!count_cols.empty() &&
                   count_cols[0].logical_type.find("BIGINT") != std::string::npos,
               "count(*) prepares as BIGINT");
        Expect(MapTypeName(count_cols[0].logical_type)->id() == arrow::Type::INT64,
               "count(*) maps to int64");
    }
}
