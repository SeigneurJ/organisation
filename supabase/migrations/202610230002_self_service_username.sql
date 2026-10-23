-- The Edge Function must verify the caller's confirmed JWT, then pass that
-- exact auth.users id here. This privileged RPC is never executable by clients.
-- Review this authorization change before applying it to a Supabase project.
create or replace function public.organisation_update_username_for_account(
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
     and access.status = 'approved'
  returning access.username into assigned_username;

  if assigned_username is null then
    raise exception 'account_not_available' using errcode = 'P0002';
  end if;
  return assigned_username;
exception
  when unique_violation then
    raise exception 'username_unavailable' using errcode = '23505';
end;
$$;

revoke all on function public.organisation_update_username_for_account(uuid, text) from public, anon, authenticated;
grant execute on function public.organisation_update_username_for_account(uuid, text) to service_role;

comment on function public.organisation_update_username_for_account(uuid, text) is
  'Service-role-only update for an approved account. The username-auth Edge Function must pass only the user id verified from the caller JWT.';
