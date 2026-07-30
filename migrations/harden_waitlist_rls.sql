-- The waitlist is accessed only by the server-side Supabase service role.
-- Block direct browser access through the anon/authenticated API keys.
alter table public.waitlist enable row level security;

revoke all privileges on table public.waitlist from anon, authenticated;

-- Remove any legacy browser-facing policies. The service role bypasses RLS.
do $$
declare
  policy_record record;
begin
  for policy_record in
    select policyname
    from pg_policies
    where schemaname = 'public' and tablename = 'waitlist'
  loop
    execute format(
      'drop policy if exists %I on public.waitlist',
      policy_record.policyname
    );
  end loop;
end
$$;

alter table public.waitlist
  add column if not exists verification_email_window_start timestamptz,
  add column if not exists verification_email_send_count integer not null default 0;

alter table public.waitlist
  drop constraint if exists waitlist_verification_email_send_count_check;
alter table public.waitlist
  add constraint waitlist_verification_email_send_count_check
  check (verification_email_send_count between 0 and 3);

-- Atomically reserve at most three verification sends per address per hour.
create or replace function public.reserve_waitlist_verification_email(
  target_email text
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  signup public.waitlist%rowtype;
begin
  select * into signup
  from public.waitlist
  where email = lower(target_email)
  for update;

  if not found then
    return 'missing';
  end if;
  if signup.verified_at is not null then
    return 'verified';
  end if;

  if signup.verification_email_window_start is null
     or signup.verification_email_window_start < now() - interval '1 hour' then
    update public.waitlist
    set verification_email_window_start = now(),
        verification_email_send_count = 1
    where id = signup.id;
    return 'send';
  end if;

  if signup.verification_email_send_count >= 3 then
    return 'limited';
  end if;

  update public.waitlist
  set verification_email_send_count = verification_email_send_count + 1
  where id = signup.id;
  return 'send';
end
$$;

revoke all on function public.reserve_waitlist_verification_email(text)
  from public, anon, authenticated;
grant execute on function public.reserve_waitlist_verification_email(text)
  to service_role;
