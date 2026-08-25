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

-- NetSentinel — Phase 2: feature engineering & host baseline
-- Run once in the Supabase SQL editor. Idempotent (if not exists / add
-- column if not exists) -- safe to re-run the whole file.

alter table flows add column if not exists packets_fwd integer;
alter table flows add column if not exists packets_bwd integer;
alter table flows add column if not exists bytes_fwd bigint;
alter table flows add column if not exists bytes_bwd bigint;
alter table flows add column if not exists saw_syn boolean;
alter table flows add column if not exists saw_syn_ack boolean;
alter table flows add column if not exists close_reason text;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'flows_close_reason_check'
  ) then
    alter table flows add constraint flows_close_reason_check
      check (close_reason in ('fin_fin', 'rst', 'timeout', 'eof'));
  end if;
end $$;

create table if not exists flow_features (
  flow_id uuid primary key references flows(id) on delete cascade,
  duration_seconds double precision not null,
  packets_per_second double precision not null,
  bytes_per_second double precision not null,
  avg_packet_size double precision not null,
  is_bidirectional boolean not null,
  handshake_completed boolean,
  close_type text,
  computed_at timestamptz not null default now()
);
grant select, insert, update, delete on public.flow_features to service_role;

create table if not exists host_profiles (
  ip inet primary key,
  flow_count integer not null,
  total_bytes bigint not null,
  unique_dst_ports_contacted integer not null,
  first_seen timestamptz not null,
  last_seen timestamptz not null,
  updated_at timestamptz not null default now()
);
grant select, insert, update, delete on public.host_profiles to service_role;

-- Same RLS rationale as flows: service_role only, no frontend-direct
-- access to either new table yet.
