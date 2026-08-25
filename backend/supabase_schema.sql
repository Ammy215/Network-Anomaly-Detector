-- NetSentinel — Phase 1: flows table
-- Run once in the Supabase SQL editor (Project → SQL Editor → New query).

create table if not exists flows (
  id uuid primary key default gen_random_uuid(),
  source_file text not null,
  src_ip inet not null,
  dst_ip inet not null,
  src_port integer,
  dst_port integer,
  protocol text not null,
  packet_count integer not null,
  byte_count bigint not null,
  started_at timestamptz not null,
  ended_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists flows_started_at_idx on flows (started_at desc);

-- Bypassing RLS (what service_role does) is not the same as having
-- table-level privileges — Postgres checks GRANTs independently of RLS.
-- Supabase usually wires up default privileges for public-schema tables
-- automatically, but this project's setup didn't cover this table, so
-- it's explicit here.
grant select, insert, update, delete on public.flows to service_role;

-- RLS is enabled at the project level (Supabase's default) with no
-- policies defined on this table yet. That's fine for now: the backend
-- reads/writes via the service_role key, which bypasses RLS regardless
-- of policy state, and the frontend never talks to Supabase directly.
-- Real per-user policies are needed before Phase 9 introduces any
-- frontend-direct or per-user access to this table.
