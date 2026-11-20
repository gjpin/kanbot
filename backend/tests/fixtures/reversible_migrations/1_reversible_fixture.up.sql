-- Used by tests/health.rs: a reversible migration, whose down half must not
-- count as pending.
CREATE TABLE reversible_fixture (id integer PRIMARY KEY);
