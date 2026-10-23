-- Access approval for Organisation.
-- Apply only after reviewing the application contract. This migration does not
-- grant administrator status to any account; the owner UUID must be bootstrapped
-- manually after it has been verified in Supabase Auth.

begin;

create schema if not exists organisation_private;
revoke all on schema organisation_private from public, anon, authenticated, service_role;

create table if not exists organisation_private.organisation_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table organisation_private.organisation_admins enable row level security;
revoke all on table organisation_private.organisation_admins from public, anon, authenticated, service_role;

create table if not exists public.organisation_access (
  user_id uuid primary key references auth.users (id) on delete cascade,
  email text,
  display_name text not null default 'Utilisateur'
    check (char_length(display_name) between 1 and 80),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'suspended')),
  requested_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users (id) on delete set null
);

alter table public.organisation_access enable row level security;
revoke all on table public.organisation_access from public, anon, authenticated;
grant select on table public.organisation_access to authenticated;

create or replace function public.organisation_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select auth.uid() is not null and exists (
    select 1
    from organisation_private.organisation_admins as admins
    where admins.user_id = auth.uid()
  );
$$;

create or replace function public.organisation_is_approved()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select auth.uid() is not null and exists (
    select 1
    from public.organisation_access as access
    where access.user_id = auth.uid()
      and access.status = 'approved'
  );
$$;

revoke all on function public.organisation_is_admin() from public, anon;
grant execute on function public.organisation_is_admin() to authenticated;
revoke all on function public.organisation_is_approved() from public, anon;
grant execute on function public.organisation_is_approved() to authenticated;

drop policy if exists "Users can read their own organisation access" on public.organisation_access;
create policy "Users can read their own organisation access"
  on public.organisation_access for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select public.organisation_is_admin())
  );

create or replace function public.request_organisation_access(p_display_name text default null)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_user_id uuid := auth.uid();
  current_email text;
  auth_display_name text;
  requested_display_name text;
  current_status text;
begin
  if current_user_id is null then
    raise exception 'not_authenticated' using errcode = '42501';
  end if;

  select users.email,
         coalesce(
           nullif(left(btrim(coalesce(users.raw_user_meta_data ->> 'display_name', '')), 80), ''),
           nullif(left(split_part(coalesce(users.email, ''), '@', 1), 80), ''),
           'Utilisateur'
         )
    into current_email, auth_display_name
    from auth.users as users
   where users.id = current_user_id;

  if not found then
    raise exception 'auth_user_not_found' using errcode = '42501';
  end if;

  requested_display_name := coalesce(
    nullif(left(btrim(coalesce(p_display_name, '')), 80), ''),
    auth_display_name
  );

  -- The client can create only a pending request for its authenticated UUID.
  -- Existing statuses are never changed by this function.
  insert into public.organisation_access (user_id, email, display_name, status)
  values (current_user_id, current_email, requested_display_name, 'pending')
  on conflict (user_id) do nothing;

  select access.status
    into current_status
    from public.organisation_access as access
   where access.user_id = current_user_id;

  return current_status;
end;
$$;

revoke all on function public.request_organisation_access(text) from public, anon;
grant execute on function public.request_organisation_access(text) to authenticated;

create or replace function public.set_organisation_access_status(
  p_user_id uuid,
  p_status text
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  updated_status text;
begin
  if auth.uid() is null or not public.organisation_is_admin() then
    raise exception 'not_authorised' using errcode = '42501';
  end if;

  if p_user_id is null or p_status is null
     or p_status not in ('pending', 'approved', 'rejected', 'suspended') then
    raise exception 'invalid_access_status' using errcode = '22023';
  end if;

  if p_status <> 'approved' and exists (
    select 1
    from organisation_private.organisation_admins as admins
    where admins.user_id = p_user_id
  ) then
    raise exception 'cannot_suspend_administrator' using errcode = '42501';
  end if;

  update public.organisation_access as access
     set status = p_status,
         updated_at = now(),
         reviewed_at = case when p_status = 'pending' then null else now() end,
         reviewed_by = case when p_status = 'pending' then null else auth.uid() end
   where access.user_id = p_user_id
  returning access.status into updated_status;

  if updated_status is null then
    raise exception 'access_request_not_found' using errcode = 'P0002';
  end if;

  return updated_status;
end;
$$;

revoke all on function public.set_organisation_access_status(uuid, text) from public, anon;
grant execute on function public.set_organisation_access_status(uuid, text) to authenticated;

-- Auth metadata is copied for display only; it never determines administrator
-- authority or the access status. These triggers create new users as pending.
create or replace function public.handle_organisation_auth_user_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  safe_display_name text;
begin
  safe_display_name := nullif(left(btrim(coalesce(new.raw_user_meta_data ->> 'display_name', '')), 80), '');
  if safe_display_name is null then
    safe_display_name := coalesce(
      nullif(left(split_part(coalesce(new.email, ''), '@', 1), 80), ''),
      'Utilisateur'
    );
  end if;

  insert into public.organisation_access (user_id, email, display_name, status, requested_at)
  values (new.id, new.email, safe_display_name, 'pending', coalesce(new.created_at, now()))
  on conflict (user_id) do nothing;

  return new;
end;
$$;

create or replace function public.handle_organisation_auth_user_update()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  safe_display_name text;
begin
  safe_display_name := nullif(left(btrim(coalesce(new.raw_user_meta_data ->> 'display_name', '')), 80), '');
  if safe_display_name is null then
    safe_display_name := coalesce(
      nullif(left(split_part(coalesce(new.email, ''), '@', 1), 80), ''),
      'Utilisateur'
    );
  end if;

  update public.organisation_access
     set email = new.email,
         display_name = safe_display_name,
         updated_at = now()
   where user_id = new.id;

  return new;
end;
$$;

revoke all on function public.handle_organisation_auth_user_insert() from public, anon, authenticated, service_role;
revoke all on function public.handle_organisation_auth_user_update() from public, anon, authenticated, service_role;
grant execute on function public.handle_organisation_auth_user_insert() to supabase_auth_admin;
grant execute on function public.handle_organisation_auth_user_update() to supabase_auth_admin;

drop trigge