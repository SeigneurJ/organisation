-- Bootstrap the single owner administrator after the access migration has
-- been approved and applied, and after the owner's Auth UUID has been checked
-- directly in Supabase Authentication > Users.
--
-- Replace the all-zero UUID below with that verified Auth UUID before running
-- this file in the Supabase SQL Editor. Leaving the placeholder unchanged
-- intentionally raises an exception and makes no changes.
-- Never put an email address, password, or secret key in this file.

begin;

do $bootstrap$
declare
  owner_id constant uuid := '00000000-0000-0000-0000-000000000000';
begin
  if owner_id = '00000000-0000-0000-0000-000000000000'::uuid then
    raise exception 'Replace the placeholder with the verified owner Auth UUID';
  end if;

  if not exists (
    select 1 from auth.users where id = owner_id
  ) then
    raise exception 'The supplied UUID does not exist in Supabase Auth';
  end if;

  if not exists (
    select 1 from public.organisation_access where user_id = owner_id
  ) then
    raise exception 'No access request exists for this Auth UUID; check that migration 002 is applied';
  end if;

  insert into organisation_private.organisation_admins (user_id)
  values (owner_id)
  on conflict (user_id) do nothing;

  update public.organisation_access
     set status = 'approved',
         updated_at = now(),
         reviewed_at = now(),
         reviewed_by = owner_id
   where user_id = owner_id;
end;
$bootstrap$;

commit;
