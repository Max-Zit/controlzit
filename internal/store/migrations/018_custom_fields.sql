-- Custom fields administrators define for devices and customers (asset
-- number, warranty end, contract, …) and their values.
CREATE TABLE custom_fields (
    id         bigserial PRIMARY KEY,
    scope      text NOT NULL CHECK (scope IN ('device', 'customer')),
    name       text NOT NULL,
    kind       text NOT NULL DEFAULT 'text' CHECK (kind IN ('text', 'number', 'date')),
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX custom_fields_name ON custom_fields (scope, lower(name));

CREATE TABLE device_field_values (
    field_id  bigint NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
    device_id bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    value     text NOT NULL,
    PRIMARY KEY (field_id, device_id)
);

CREATE TABLE customer_field_values (
    field_id    bigint NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    value       text NOT NULL,
    PRIMARY KEY (field_id, customer_id)
);
