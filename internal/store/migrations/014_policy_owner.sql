-- A policy can belong to one customer: technicians of that customer manage
-- it and it can only be assigned within that customer. NULL: a policy of
-- the whole server (administrators only).
ALTER TABLE policies ADD COLUMN customer_id bigint REFERENCES customers(id) ON DELETE CASCADE;
ALTER TABLE policies DROP CONSTRAINT policies_name_key;
CREATE UNIQUE INDEX policies_name ON policies (COALESCE(customer_id, 0), lower(name));
