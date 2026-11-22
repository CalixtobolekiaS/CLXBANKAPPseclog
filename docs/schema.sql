-- Run this once in Supabase: SQL Editor > New query > paste > Run
create table if not exists config (id int primary key, salt text not null, cfg jsonb not null);
create table if not exists users (
  username text primary key, salt text not null, hash text not null,
  role text not null check (role in ('admin','manager','auditor','user')),
  rec jsonb not null, fails int not null default 0, lock_until bigint not null default 0,
  created bigint not null, created_by text);
create table if not exists deleted_users (name text primary key, role text, ts bigint, deleted_by text, created bigint, replaced_by text);
create table if not exists audit_log (id bigserial primary key, ts bigint not null, actor text, event text not null, detail text, mac text not null);
create table if not exists backups (id bigserial primary key, ts bigint not null, kind text, salt text, iv text, ct text, mac text);

alter table config enable row level security;
alter table users enable row level security;
alter table deleted_users enable row level security;
alter table audit_log enable row level security;
alter table backups enable row level security;

-- DEMO policies (the app does its own login, so the public anon key must be allowed to read/write).
create policy cfg_s on config for select to anon using (true);
create policy cfg_i on config for insert to anon with check (true);
create policy cfg_u on config for update to anon using (true) with check (true);
create policy usr_s on users for select to anon using (true);
create policy usr_i on users for insert to anon with check (true);
create policy usr_u on users for update to anon using (true) with check (true);
create policy usr_d on users for delete to anon using (true);
create policy del_s on deleted_users for select to anon using (true);
create policy del_i on deleted_users for insert to anon with check (true);
create policy del_u on deleted_users for update to anon using (true) with check (true);
-- audit_log: insert and read only. Nobody can edit or delete entries (append-only trail).
create policy aud_s on audit_log for select to anon using (true);
create policy aud_i on audit_log for insert to anon with check (true);
create policy bak_s on backups for select to anon using (true);
create policy bak_i on backups for insert to anon with check (true);
create policy bak_u on backups for update to anon using (true) with check (true);
create policy bak_d on backups for delete to anon using (true);
