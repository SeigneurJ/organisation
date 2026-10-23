-- Assign the existing, verified owner a private login username after applying
-- migration 003. Replace BOTH placeholders in a private SQL Editor session only.
-- Do not commit or publish this customized copy. This template changes only the
-- owner username, never an Auth password, email, or administrator role.

begin;

do $bootstrap_username$
declare
  owner_id constant uuid := '00000000-0000-0000-0000-000000000000';
  owner_username constant text := 'REPLACE_WITH_USERNAME';
  normalized_username text;
begin
  if owner_id = '00000000-0000-0000-0000-000000000000'::uuid then
    raise exception 'Replace the placeholder with the verified owner Auth UUID';
  end if;
  if owner_username = 'REPLACE_WITH_USERNAME' then
    raise exception 'Replace the placeholder with the owner-chosen username';
  end if;
  if not exists (select 1 from auth.users where id = owner_id) then
    raise exception 'The supplied UUID does not exist in Supabase Auth';
  end if;
  if not exists (select 1 from organisation_private.organisation_admins where user_id = owner_id) then
    raise exception 'The supplied UUID is not the bootstrapped owner administrator';
  end if;

  normalized_username := normalize(btrim(owner_username), NFC);
  if char_length(normalized_username) not between 3 and 32
     or normalized_username !~ '^[A-Za-z][A-Za-z0-9_.-]{2,31}$' then
    raise exception 'The chosen username is invalid';
  end if;

  update public.organisation_access
     set username = normalized_username,
         updated_at = now()
   where user_id = owner_id;
  if not found then
    raise exception 'The owner access row is missing; check migration 002';
  end if;
end;
$bootstrap_username$;

commit;
