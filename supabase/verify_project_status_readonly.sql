-- One-row, read-only project status check for migrations 001/002/003.
-- Returns only object names and boolean/count checks; no UUIDs, emails, or app data.
with objects as (
  select to_regclass('public.organisation_states') as state_table,
         to_regclass('public.organisation_access') as access_table,
         to_regclass('organisation_private.organisation_admins') as admins_table,
         to_regprocedure('public.save_organisation_state(jsonb,bigint,uuid)') as save_rpc,
         to_regprocedure('public.save_organisation_state(jsonb,bigint)') as old_save_rpc,
         to_regprocedure('public.organisation_is_approved()') as approved_rpc,
         to_regprocedure('public.organisation_is_admin()') as admin_rpc,
         to_regprocedure('public.organisation_resolve_username_for_auth(text)') as username_resolver,
         to_regprocedure('public.organisation_claim_username_for_user(uuid,text)') as username_claim,
         to_regprocedure('public.organisation_consume_username_auth_attempt(text,text)') as username_limiter
), checks as (
  select objects.*,
         coalesce((select relation.relrowsecurity from pg_class as relation where relation.oid = objects.state_table), false) as state_rls,
         coalesce((select relation.relrowsecurity from pg_class as relation where relation.oid = objects.access_table), false) as access_rls,
         coalesce((select relation.relrowsecurity from pg_class as relation where relation.oid = objects.admins_table), false) as admins_rls,
         coalesce(has_table_privilege('anon', objects.state_table, 'SELECT'), false) as anon_state_select,
         coalesce(has_table_privilege('authenticated', objects.state_table, 'SELECT'), false) as auth_state_select,
         coalesce(has_table_privilege('authenticated', objects.state_table, 'INSERT'), false) as auth_state_insert,
         coalesce(has_table_privilege('authenticated', objects.state_table, 'UPDATE'), false) as auth_state_update,
         coalesce(has_table_privilege('authenticated', objects.state_table, 'DELETE'), false) as auth_state_delete,
         coalesce(has_table_privilege('anon', objects.access_table, 'SELECT'), false) as anon_access_select,
         coalesce(has_table_privilege('authenticated', objects.access_table, 'SELECT'), false) as auth_access_select,
         coalesce(has_table_privilege('authenticated', objects.access_table, 'INSERT'), false) as auth_access_insert,
         coalesce(has_table_privilege('authenticated', objects.access_table, 'UPDATE'), false) as auth_access_update,
         coalesce(has_table_privilege('authenticated', objects.access_table, 'DELETE'), false) as auth_access_delete,
         coalesce(has_table_privilege('anon', objects.admins_table, 'SELECT'), false) as anon_admins_select,
         coalesce(has_table_privilege('authenticated', objects.admins_table, 'SELECT'), false) as auth_admins_select,
         coalesce((select count(*) from organisation_private.organisation_admins), 0) as admin_count,
         exists (
           select 1
             from pg_constraint as constraint_row
            where constraint_row.conrelid = objects.admins_table
              and constraint_row.contype = 'p'
              and (
                select array_agg(attribute.attname order by key_column.ordinality)
                  from unnest(constraint_row.conkey) with ordinality as key_column(attnum, ordinality)
                  join pg_attribute as attribute
                    on attribute.attrelid = objects.admins_table
                   and attribute.attnum = key_column.attnum
              ) = array['user_id']::name[]
         ) as admin_user_id_primary_key,
         exists (
           select 1 from pg_policies
            where schemaname = 'public' and tablename = 'organisation_states'
              and cmd = 'SELECT' and coalesce(qual, '') like '%organisation_is_approved%'
         ) as approved_state_select_policy,
         exists (
           select 1 from information_schema.columns
            where table_schema = 'public' and table_name = 'organisation_access'
              and column_name = 'username'
         ) as username_column_exists,
         coalesce(has_function_privilege('authenticated', objects.save_rpc, 'EXECUTE'), false) as auth_can_execute_save_rpc,
         coalesce(has_function_privilege('anon', objects.save_rpc, 'EXECUTE'), false) as anon_can_execute_save_rpc,
         coalesce((select procedure.prosecdef from pg_proc as procedure where procedure.oid = objects.save_rpc), false) as save_rpc_security_definer,
         coalesce((select exists (
           select 1 from unnest(procedure.proconfig) as setting
            where setting like 'search_path=%'
         ) from pg_proc as procedure where procedure.oid = objects.save_rpc), false) as save_rpc_has_fixed_search_path,
         coalesce(has_function_privilege('service_role', objects.username_resolver, 'EXECUTE'), false) as service_can_resolve_username,
         coalesce(has_function_privilege('authenticated', objects.username_resolver, 'EXECUTE'), false) as auth_can_resolve_username,
         coalesce(has_function_privilege('service_role', objects.username_claim, 'EXECUTE'), false) as service_can_claim_username,
         coalesce(has_function_privilege('service_role', objects.username_limiter, 'EXECUTE'), false) as service_can_use_rate_limiter
    from objects
)
select
  (
    state_table is not null and access_table is not null and admins_table is not null
    and state_rls and access_rls and admins_rls
    and not anon_state_select and auth_state_select
    and not auth_state_insert and not auth_state_update and not auth_state_delete
    and not anon_access_select and auth_access_select
    and not auth_access_insert and not auth_access_update and not auth_access_delete
    and not anon_admins_select and not auth_admins_select
    and save_rpc is not null and old_save_rpc is null
    and auth_can_execute_save_rpc and not anon_can_execute_save_rpc
    and save_rpc_security_definer and save_rpc_has_fixed_search_path
    and approved_rpc is not null and admin_rpc is not null
    and approved_state_select_policy
    and admin_count = 1 and admin_user_id_primary_key
  ) as base_access_setup_ready,
  (username_column_exists and username_resolver is not null and username_claim is not null
    and username_limiter is not null and service_can_resolve_username
    and not auth_can_resolve_username and service_can_claim_username
    and service_can_use_rate_limiter) as username_auth_migration_003_present,
  admin_count,
  state_table is not null as organisation_states_exists,
  state_rls as organisation_states_rls_enabled,
  access_table is not null as organisation_access_exists,
  access_rls as organisation_access_rls_enabled,
  admins_table is not null as organisation_admins_exists,
  admins_rls as organisation_admins_rls_enabled,
  (not anon_state_select and auth_state_select
    and not auth_state_insert and not auth_state_update and not auth_state_delete) as state_grants_match,
  (not anon_access_select and auth_access_select
    and not auth_access_insert and not auth_access_update and not auth_access_delete) as access_grants_match,
  (not anon_admins_select and not auth_admins_select) as admin_registry_not_readable_by_clients,
  approved_state_select_policy,
  (save_rpc is not null and old_save_rpc is null) as expected_save_signature_only,
  (auth_can_execute_save_rpc and not anon_can_execute_save_rpc
    and save_rpc_security_definer and save_rpc_has_fixed_search_path) as save_rpc_permissions_match,
  (admin_count = 1 and admin_user_id_primary_key) as exactly_one_admin_with_uuid_primary_key
from checks;
