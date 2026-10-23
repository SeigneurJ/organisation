create table if not exists public.organisation_states (
  user_id uuid primary key references auth.users (id) on delete cascade,
  state jsonb not null default '{}'::jsonb,
  version bigint not null default 1 check (version > 0),
  updated_at timestamptz not null default now(),
  constraint organisation_states_state_is_object check (jsonb_typeof(state) = 'object'),
  constraint organisation_states_state_size check (pg_column_size(state) <= 1048576)
);

alter table public.organisation_states enable row level security;

revoke all on table public.organisation_states from anon, authenticated;
grant select, insert, update on table public.organisation_states to authenticated;

drop policy if exists "Users can read their own organisation state" on public.organisation_states;
create policy "Users can read their own organisation state"
  on public.organisation_states for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can insert their own organisation state" on public.organisation_states;
create policy "Users can insert their own organisation state"
  on public.organisation_states for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their own organisation state" on public.organisation_states;
create policy "Users can update their own organisation state"
  on public.organisation_states for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create or replace function public.save_organisation_state(
  p_state jsonb,
  p_expected_version bigint
)
returns bigint
language plpgsql
security invoker
set search_path = ''
as $$
declare
  next_version bigint;
begin
  if auth.uid() is null then
    raise exception 'not_authenticated' using errcode = '42501';
  end if;

  if p_expected_version is null or p_expected_version < 0 then
    raise exception 'invalid_expected_version' using errcode = '22023';
  end if;

  if jsonb_typeof(p_state) is distinct from 'object' then
    raise exception 'state_must_be_object' using errcode = '22023';
  end if;

  if pg_column_size(p_state) > 1048576 then
    raise exception 'state_too_large' using errcode = '22023';
  end if;

  if p_expected_version = 0 then
    insert into public.organisation_states (user_id, state, version, updated_at)
    values (auth.uid(), p_state, 1, now())
    on conflict (user_id) do nothing
    returning version into next_version;
  else
    update public.organisation_states
    set state = p_state,
        version = version + 1,
        updated_at = now()
    where user_id = auth.uid()
      and version = p_expected_version
    returning version into next_version;
  end if;

  if next_version is null then
    raise exception 'state_conflict' using errcode = '40001';
  end if;

  return next_version;
end;
$$;

revoke all on function public.save_organisation_state(jsonb, bigint) from public, anon;
grant execute on function public.save_organisation_state(jsonb, bigint) to authenticated;
