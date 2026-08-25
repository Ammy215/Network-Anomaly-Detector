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

-- NetSentinel — Phase 3: ML detection (model registry + per-flow scores)
-- Run once in the Supabase SQL editor. Idempotent — safe to re-run.

-- Insert-only registry. A retrain adds a row; it never updates one, so a
-- model is never silently replaced and old scores stay interpretable.
create table if not exists model_versions (
  id uuid primary key default gen_random_uuid(),
  algorithm text not null,
  variant text not null default 'primary',
  feature_list jsonb not null,
  training_set_size integer not null,
  training_source_files jsonb not null,
  hyperparameters jsonb not null,
  random_seed integer,
  threshold double precision not null,
  threshold_strategy text not null,
  metrics jsonb not null,
  artifact_path text,
  created_at timestamptz not null default now()
);
grant select, insert, update, delete on public.model_versions to service_role;

-- Scores are keyed by (flow, model version) so two models can score the
-- same flow and both answers survive.
create table if not exists flow_scores (
  flow_id uuid not null references flows(id) on delete cascade,
  model_version_id uuid not null references model_versions(id) on delete cascade,
  anomaly_score double precision not null,
  raw_score double precision not null,
  is_anomalous boolean not null,
  top_features jsonb not null,
  scored_at timestamptz not null default now(),
  primary key (flow_id, model_version_id)
);
create index if not exists flow_scores_model_idx on flow_scores (model_version_id);
create index if not exists flow_scores_score_idx on flow_scores (anomaly_score desc);
grant select, insert, update, delete on public.flow_scores to service_role;

-- Which model is actually shipped. Previously the UI picked whichever row
-- was inserted last, so it silently displayed a different model than the
-- one being discussed -- see docs/ML-MODEL-NOTES.md for the concrete
-- 996-flow disagreement that exposed this. The DB is the single source of
-- truth; the code constant is only a fallback when nothing is marked.
alter table model_versions add column if not exists is_active boolean not null default false;

-- Enforces "at most one active model" in the database rather than trusting
-- application code to maintain it.
create unique index if not exists model_versions_one_active_idx
  on model_versions (is_active) where is_active = true;

-- NetSentinel — Phase 3.1: stable flow sequence number
-- Run once in the Supabase SQL editor. Idempotent -- safe to re-run.
--
-- The UUID primary key has no order of its own, so there was no stable,
-- permanent row number for the flows table -- the UI could only show
-- insertion-sensitive things like started_at. This adds a real bigint
-- identity column, backed by a sequence, that never changes once assigned.

create sequence if not exists flows_seq_seq;

alter table flows add column if not exists seq bigint;

-- Backfill rows that existed before this column did. created_at was set
-- at insert time, so ordering by it (with id as a tiebreaker for equal
-- timestamps) reconstructs true insertion order for the backfill.
update flows set seq = ordered.rn
from (
  select id, row_number() over (order by created_at asc, id asc) as rn
  from flows
  where seq is null
) as ordered
where flows.id = ordered.id;

-- Advance the sequence past the backfilled values so new inserts continue
-- the numbering instead of colliding with it.
select setval('flows_seq_seq', coalesce((select max(seq) from flows), 0));

alter table flows alter column seq set default nextval('flows_seq_seq');
alter table flows alter column seq set not null;
alter sequence flows_seq_seq owned by flows.seq;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'flows_seq_unique'
  ) then
    alter table flows add constraint flows_seq_unique unique (seq);
  end if;
end $$;

create index if not exists flows_seq_idx on flows (seq);

-- NetSentinel — Phase 4: score transparency & verdict/feedback loop
-- Run once in the Supabase SQL editor. Idempotent -- safe to re-run.
--
-- One row per flow (flow_id is the primary key, not part of a composite
-- key) so "one verdict per flow, re-marking overwrites" is a database
-- guarantee, not application logic. The verdict is the analyst's
-- ground-truth judgement about the flow's actual behaviour -- deliberately
-- independent of whether the active model flagged it, which is what lets
-- a flow verdicted true_positive with is_anomalous=false represent a
-- missed detection (see docs -- Phase 4 plan) without a separate enum
-- value for it.

create table if not exists flow_verdicts (
  flow_id uuid primary key references flows(id) on delete cascade,
  verdict text not null check (verdict in ('true_positive', 'false_positive', 'benign', 'unknown')),
  note text,
  created_by text not null default 'local-analyst',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
grant select, insert, update, delete on public.flow_verdicts to service_role;

create index if not exists flow_verdicts_verdict_idx on flow_verdicts (verdict);
