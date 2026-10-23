-- Read-only verification for the access-approval setup.
-- Run after migration 002 and the owner bootstrap have been applied.
-- This script only reads PostgreSQL catalogs and counts admin rows. It does
-- not return Auth UUIDs, read application data, or modify any account/object.

begin transaction read only;

-- 1. Required tables and row-level security state.
with expected(schema_name, table_name) as (
  values
    ('public', 'organisation_states'),
    ('public', 'organisation_access'),
    ('organisation_private', 'organisation_admins')
)
select expected.schema_name,
       expected.table_name,
       relation.oid is not null as table_exists,
       coalesce(relation.relrowsecurity, false) as rls_enabled,
       coalesce(relation.relforcerowsecurity, false) as rls_forced
  from expected
  left join pg_namespace as namespace
    on namespace.nspname = expected.schema_name
  left join pg_class as relation
    on relation.relnamespace = namespace.oid
   and relation.relname = expected.table_name
   and relation.relkind in ('r', 'p')
 order by expected.schema_name, expected.table_name;

-- 2. Effective table privileges for browser roles. The application state
-- must be readable only by authenticated users and have no direct DML grant.
select 'organisation_states' as table_name,
       has_table_privilege('anon', 'public.organisation_states', 'SELECT') as anon_select,
       has_table_privilege('authenticated', 'public.organisation_states', 'SELECT') as authenticated_select,
       has_table_privilege('authenticated', 'public.organisation_states', 'INSERT') as authenticated_insert,
       has_table_privilege('authenticated', 'public.organisation_states', 'UPDATE') as authenticated_update,
       has_table_privilege('authenticated', 'public.organisation_states', 'DELETE') as authenticated_delete
union all
select 'organisation_access',
       has_table_privilege('anon', 'public.organisation_access', 'SELECT'),
       has_table_privilege('authenticated', 'public.organisation_access', 'SELECT'),
       has_table_privilege('authenticated', 'public.organisation_access', 'INSERT'),
       has_table_privilege('authenticated', 'public.organisation_access', 'UPDATE'),
       has_table_privilege('authenticated', 'public.organisation_access', 'DELETE')
union all
select 'organisation_private.organisation_admins',
       has_table_privilege('anon', 'organisation_private.organisation_admins', 'SELECT'),
       has_table_privilege('authenticated', 'organisation_private.organisation_admins', 'SELECT'),
       has_table_privilege('authenticated', 'organisation_private.organisation_admins', 'INSERT'),
       has_table_privilege('authenticated', 'organisation_private.organisation_admins', 'UPDATE'),
       has_table_privilege('authenticated', 'organisation_private.organisation_admins', 'DELETE');

-- 3. RLS policies currently installed on the protected application tables.
select schemaname,
       tablename,
       policyname,
       permissive,
       roles,
       cmd,
       qual,
       with_check
  from pg_policies
 where (schemaname = 'public' and tablename in ('organisation_states', 'organisation_access'))
    or (schemaname = 'organisation_private' and tablename = 'organisation_admins')
 order by schemaname, tablename, policyname;

-- 4. RPC identities, result types, SECURITY DEFINER setting, and effective
-- browser-role execution privileges. The obsolete two-argument save overload
-- is checked separately below.
select p.proname as function_name,
       pg_get_function_identity_arguments(p.oid) as arguments,
       pg_get_function_result(p.oid) as result_type,
       p.prosecdef as security_definer,
       p.proconfig as function_settings,
       has_function_privilege('anon', p.oid, 'EXECUTE') as anon_execute,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_execute
  from pg_proc as p
  join pg_namespace as namespace on namespace.oid = p.pronamespace
 where namespace.nspname = 'public'
   and p.proname in (
     'organisation_is_admin',
     'organisation_is_approved',
     'request_organisation_access',
     'set_organisation_access_status',
     'save_organisation_state'
   )
  order by p.proname, pg_get_function_identity_arguments(p.oid);

select to_regprocedure('public.save_organisation_state(jsonb,bigint)') is null
  as obsolete_two_argument_save_signature_absent,
       to_regprocedure('public.save_organisation_state(jsonb,bigint,uuid)') is not null
  as expected_three_argument_save_signature_present;

-- 5. Admin registry integrity without exposing the administrator UUID.
select count(*) as admin_count,
       count(*) = 1 as exactly_one_admin_registered
  from organisation_private.organisation_admins;

select exists (
  select 1
    from pg_constraint as constraint_row
    join pg_class as relation on relation.oid = constraint_row.conrelid
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
   where namespace.nspname = 'organisation_private'
     and relation.relname = 'organisation_admins'
     and constraint_row.contype = 'p'
     and (
       select array_agg(attribute.attname order by key_column.ordinality)
         from unnest(constraint_row.conkey) with ordinality as key_column(attnum, ordinality)
         join pg_attribute as attribute
           on attribute.attrelid = relation.oid
          and attribute.attnum = key_column.attnum
     ) = array['user_id']::name[]
) as admin_uuid_has_unique_primary_key;

commit;
