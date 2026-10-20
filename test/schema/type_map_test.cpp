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

    auto dec = MapTypeName("DECIMAL(10,2)");
    Expect(dec && dec->id() == arrow::Type::DECIMAL128, "DECIMAL maps to decimal128");
    if (dec && dec->id() == arrow::Type::DECIMAL128) {
        auto *d = static_cast<arrow::Decimal128Type *>(dec.get());
        Expect(d->precision() == 10 && d->scale() == 2, "DECIMAL(10,2) keeps precision and scale");
    }

    auto bigint = MapTypeName("BIGINT");
    Expect(bigint && !bigint->Equals(*arrow::int32()), "BIGINT must not collapse to int32");

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
