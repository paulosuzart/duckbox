CREATE TABLE deals (
    tenant_id INTEGER,
    id INTEGER,
    title VARCHAR,
    amount INTEGER,
    _deleted BOOLEAN
);

INSERT INTO deals VALUES
    (21, 1, 'alpha deal', 100, false),
    (21, 2, 'alpha deleted', 1, true),
    (22, 3, 'bravo deal', 500, false),
    (22, 4, 'bravo two', 50, false);

CREATE TABLE secrets (
    tenant_id INTEGER,
    note VARCHAR
);
INSERT INTO secrets VALUES (21, 'should never be visible through duckbox');

-- Materialized lake relation (dbt/Bruin would typically emit a view or table
-- in DuckLake). Memory bootstrap may only CREATE TABLE / CREATE SCHEMA / INSERT
-- — never VIEW or MACRO — so tenants cannot query unwrapped wrappers created
-- at seed time.
CREATE TABLE deal_summaries AS
SELECT tenant_id, id, title, amount FROM deals WHERE _deleted = false;
