-- Zemtik POC: transactions table for Supabase backend.
-- Run this in the Supabase SQL Editor before using DB_BACKEND=supabase.
-- (The app also auto-creates this table on first run.)

CREATE TABLE IF NOT EXISTS transactions (
    id            BIGINT  PRIMARY KEY,
    client_id     BIGINT  NOT NULL,
    amount        BIGINT  NOT NULL,
    category      BIGINT  NOT NULL,
    category_name TEXT    NOT NULL,
    timestamp     BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transactions_client_id
    ON transactions (client_id);
