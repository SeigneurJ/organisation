-- Local proposal only. Apply only after security review and explicit approval.
-- Usernames are private identifiers for the server-side auth function; they do
-- not replace the private Auth email used for confirmation and recovery.

begin;

alter table public.organisation_access
  add column if not exists username text;

create or replace function public.organisation_normalize_username(p_username text)
returns text
language sql
immutable
strict
set search_path = ''
as $$
  select lower(normalize(btrim(p_username), NFC));
$$;

do $username_constraint$
begin
  if not exists (
    select 1
      from pg_constraint as constraint_row
     where constraint_row.conrelid = 'public.organisation_access'::regclass
       and constraint_row.conname = 'organisation_access_username_format'
  ) then
    alter table public.organisation_access
      add constraint organisation_access_username_format
      check (
        username is null
        or (
          username = btrim(username)
          and char_length(username) between 3 and 32
         and username ~ '^[A-Za-z][A-Za-z0-9_.-]{2,31}$'
        )
      );
  end if;
end;
$username_constraint$;

create unique index if not exists organisation_access_username_unique
  on public.organisation_access (public.organisation_normalize_username(username))
  where username is not null;

-- Usernames are claimed explicitly after a confirmed login. Existing display
-- names and user metadata are never treated as identifiers or reservations.

-- Claiming is performed by the public Edge Function only after it validates a
-- confirmed Auth session. The role-only grant prevents direct public lookups.
create or replace function public.organisation_claim_username_for_user(
  p_user_id uuid,
  p_username text
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  normalized_username text;
  existing_username text;
begin
  if p_user_id is null or p_username is null then
    raise exception 'username_unavailable' using errcode = '22023';
  end if;

  normalized_username := normalize(btrim(p_username), NFC);
  if char_length(normalized_username) not between 3 and 32
     or normalized_username !~ '^[A-Za-z][A-Za-z0-9_.-]{2,31}$' then
    raise exception 'username_unavailable' using errcode = '22023';
  end if;

  select access.username into existing_username
    from public.organisation_access as access
   where access.user_id = p_user_id
   for update;

  if not found then
    raise exception 'username_unavailable' using errcode = 'P0002';
  end if;

  if existing_username is not null then
    if public.organisation_normalize_username(existing_username)
       = public.organisation_normalize_username(normalized_username) then
      return existing_username;
    end if;
    raise exception 'username_unavailable' using errcode = '23505';
  end if;

  update public.organisation_access as access
     set username = normalized_username,
         updated_at = now()
   where access.user_id = p_user_id
  returning access.username into existing_username;

  return existing_username;
exception
  when unique_violation then
    raise exception 'username_unavailable' using errcode = '23505';
end;
$$;

revoke all on function public.organisation_claim_username_for_user(uuid, text) from public, anon, authenticated;
grant execute on function public.organisation_claim_username_for_user(uuid, text) to service_role;

-- Existing invited accounts can be assigned a username only by a verified
-- application administrator. This does not make the identifier publicly queryable.
create or replace function public.set_organisation_username_for_account(
  p_user_id uuid,
  p_username text
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  safe_username text;
  assigned_username text;
begin
  if auth.uid() is null or not public.organisation_is_admin() then
    raise exception 'not_authorised' using errcode = '42501';
  end if;
  if p_user_id is null or p_username is null then
    raise exception 'invalid_username' using errcode = '22023';
  end if;

  safe_username := normalize(btrim(p_username), NFC);
  if char_length(safe_username) not between 3 and 32
     or safe_username !~ '^[A-Za-z][A-Za-z0-9_.-]{2,31}$' then
    raise exception 'invalid_username' using errcode = '22023';
  end if;

  update public.organisation_access as access
     set username = safe_username,
         updated_at = now()
   where access.user_id = p_user_id
  returning access.username into assigned_username;

  if assigned_username is null then
    raise exception 'access_request_not_found' using errcode = 'P0002';
  end if;
  return assigned_username;
exception
  when unique_violation then
    raise exception 'username_unavailable' using errcode = '23505';
end;
$$;

revoke all on function public.set_organisation_username_for_account(uuid, text) from public, anon;
grant execute on function public.set_organisation_username_for_account(uuid, text) to authenticated;

-- Resolve a username only from a privileged server function. The function is
-- not executable by anon/authenticated and is intended for the Edge Function.
create or replace function public.organisation_resolve_username_for_auth(p_username text)
returns table (user_id uuid, auth_email text)
language sql
stable
security definer
set search_path = ''
as $$
  select access.user_id, users.email
    from public.organisation_access as access
    join auth.users as users on users.id = access.user_id
   where access.username is not null
     and users.email_confirmed_at is not null
     and public.organisation_normalize_username(access.username)
         = public.organisation_normalize_username(p_username)
   limit 1;
$$;

revoke all on function public.organisation_normalize_username(text) from public, anon, authenticated;
grant execute on function public.organisation_normalize_username(text) to service_role;
revoke all on function public.organisation_resolve_username_for_auth(text) from public, anon, authenticated;
grant execute on function public.organisation_resolve_username_for_auth(text) to service_role;

-- A durable atomic limiter for the public username-auth Edge Function. Only
-- keyed HMAC fingerprints are stored; raw usernames and IP addresses are not.
create table if not exists organisation_private.username_auth_rate_limits (
  bucket_hash text primary key check (bucket_hash ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz not null,
  attempts integer not null check (attempts > 0)
);

create index if not exists username_auth_rate_limits_window_idx
  on organisation_private.username_auth_rate_limits (window_started_at);

alter table organisation_private.username_auth_rate_limits enable row level security;
revoke all on table organisation_private.username_auth_rate_limits from public, anon, authenticated, service_role;

create or replace function public.organisation_consume_username_auth_attempt(
  p_ip_bucket_hash text,
  p_account_ip_bucket_hash text
)
returns table (allowed boolean, retry_after_seconds integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  ip_window timestamptz;
  ip_attempt_count integer;
  account_window timestamptz;
  account_attempt_count integer;
  seconds_left integer;
begin
  if p_ip_bucket_hash is null or p_account_ip_bucket_hash is null
     or p_ip_bucket_hash !~ '^[0-9a-f]{64}$'
     or p_account_ip_bucket_hash !~ '^[0-9a-f]{64}$'
     or p_ip_bucket_hash = p_account_ip_bucket_hash then
    raise exception 'invalid_rate_limit_fingerprint' using errcode = '22023';
  end if;

  -- Bounded opportunistic cleanup prevents stale per-username buckets growing
  -- without bound while keeping each request's database work predictable.
  with expired as (
    select bucket_hash
      from organisation_private.username_auth_rate_limits
     where window_started_at < now() - interval '1 day'
     order by window_started_at
     limit 100
  )
  delete from organisation_private.username_auth_rate_limits as limits
   using expired
   where limits.bucket_hash = expired.bucket_hash;

  insert into organisation_private.username_auth_rate_limits as limits
    (bucket_hash, window_started_at, attempts)
  values (p_ip_bucket_hash, now(), 1)
  on conflict (bucket_hash) do update
     set attempts = case
           when limits.window_started_at <= now() - interval '10 minutes' then 1
           else limits.attempts + 1
         end,
         window_started_at = case
           when limits.window_started_at <= now() - interval '10 minutes' then now()
           else limits.window_started_at
         end
  returning limits.window_started_at, limits.attempts
       into ip_window, ip_attempt_count;

  if ip_attempt_count > 30 then
    seconds_left := greatest(1, ceil(extract(epoch from (ip_window + interval '10 minutes' - now())))::integer);
    return query select false, seconds_left;
    return;
  end if;

  insert into organisation_private.username_auth_rate_limits as limits
    (bucket_hash, window_started_at, attempts)
  values (p_account_ip_bucket_hash, now(), 1)
  on conflict (bucket_hash) do update
     set attempts = case
           when limits.window_started_at <= now() - interval '10 minutes' then 1
           else limits.attempts + 1
         end,
         window_started_at = case
           when limits.window_started_at <= now() - interval '10 minutes' then now()
           else limits.window_started_at
         end
  returning limits.window_started_at, limits.attempts
       into account_window, account_attempt_count;

  seconds_left := greatest(1, ceil(extract(epoch from (account_window + interval '10 minutes' - now())))::integer);
  return query select account_attempt_count <= 5, seconds_left;
end;
$$;

revoke all on function public.organisation_consume_username_auth_attempt(text, text) from public, anon, authenticated;
grant execute on function public.organisation_consume_username_auth_attempt(text, text) to service_role;

commit;
