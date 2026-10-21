#include "check.hpp"
#include "suite.hpp"

#include "duckbox/arrow_ipc.hpp"
#include "duckbox/arrow_types.hpp"
#include "duckbox/sandbox.hpp"

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
    ExpectTypeId("ENUM('a--b', 'c')", arrow::Type::DICTIONARY,
                 "ENUM('a--b') keeps -- inside quotes");
    ExpectTypeId("ENUM('x/*y', 'z')", arrow::Type::DICTIONARY,
                 "ENUM('x/*y') keeps /* inside quotes");
    ExpectTypeId("ENUM('p$$q', 'r')", arrow::Type::DICTIONARY,
                 "ENUM('p$$q') keeps $$ inside quotes");
    ExpectTypeId("ENUM('a;b', 'c')", arrow::Type::DICTIONARY, "ENUM('a;b') keeps ; inside quotes");
    ExpectTypeId("ENUM('a''--b', 'c')", arrow::Type::DICTIONARY,
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

    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER; CREATE TABLE pwned(i INT)"); },
                        "invalid", "injection-style type name is rejected");
    ExpectThrowContains([] { (void)MapTypeName("INTEGER; CREATE TABLE pwned(i INT)"); }, "invalid",
                        "MapTypeName rejects stacked statements in a type name");
    ExpectThrowContains([] { (void)LogicalTypeFromName(std::string("INTEGER") + '\n'); }, "invalid",
                        "newline in a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName(std::string("INTEGER") + '\t'); }, "invalid",
                        "tab in a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER leftover"); }, "invalid",
                        "trailing garbage after a type name is rejected");
    ExpectThrowContains([] { (void)MapTypeName("INTEGER[] extra"); }, "invalid",
                        "trailing garbage after a nested type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("NOTATYPE"); }, "invalid",
                        "unknown type name is not VARCHAR");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER--x"); }, "invalid",
                        "SQL comment in a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER -- comment"); }, "invalid",
                        "spaced SQL comment in a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER) OR (1=1"); }, "invalid",
                        "CAST leftover OR-injection is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER), 1"); }, "invalid",
                        "extra expression after a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER/*x*/"); }, "invalid",
                        "block comment in a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("INTEGER$$x"); }, "invalid",
                        "dollar-quote in a type name is rejected");
    ExpectThrowContains([] { (void)LogicalTypeFromName("ANY"); }, "invalid",
                        "ANY is not a concrete column type");
    ExpectThrowContains([] { (void)LogicalTypeFromName("UNKNOWN"); }, "invalid",
                        "UNKNOWN is not a concrete column type");
    ExpectThrowContains([] { (void)LogicalTypeFromName("   "); }, "invalid",
                        "whitespace-only type name is rejected");
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
        TenantSandbox box(daemon, policy, key, "", MemorySpecDir());

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
