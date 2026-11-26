-- Bills from the owner's mailbox, pushed here by the Mail Hub.
--
-- The Hub is the only thing that reads Gmail. When it sees a bill (sender
-- rules, no AI) it calls hub_push_bills() with a shared secret; the page
-- shows the bills only to the owner: their regular login or the super admin.
-- No message bodies are stored: sender, a one-line summary, urgency, date.
--
-- Run once in the Supabase SQL editor (after secure_access / enable_rls).
-- Then, in the same editor:
--   1. insert into public.hub_settings (key, value) values ('owner_user_id', '<your ID>')
--        on conflict (key) do update set value = excluded.value;
--   2. select public.hub_new_push_secret();
--      and paste the result into Render as BUDGET_PUSH_SECRET (it is shown once).

create table if not exists public.hub_settings (
    key   text primary key,
    value text not null
);
alter table public.hub_settings enable row level security;
revoke all on public.hub_settings from anon, authenticated;

create table if not exists public.hub_bills (
    id          text primary key,           -- Gmail thread id
    sender      text,
    summary     text,
    urgency     text not null default 'normal',
    received_at timestamptz not null,
    done        boolean not null default false,
    created_at  timestamptz not null default now()
);
create index if not exists hub_bills_received_idx on public.hub_bills (received_at desc);
alter table public.hub_bills enable row level security;
revoke all on public.hub_bills from anon, authenticated;
grant select on public.hub_bills to anon, authenticated;
grant update (done) on public.hub_bills to anon, authenticated;

-- The owner: the super admin, or the regular user named in hub_settings.
create or replace function public.hub_is_owner() returns boolean
language sql stable security definer set search_path = public as $$
    select public.app_is_admin()
        or coalesce(public.app_uid() = (select value from public.hub_settings where key = 'owner_user_id'), false)
$$;

drop policy if exists hub_owner_select on public.hub_bills;
drop policy if exists hub_owner_update on public.hub_bills;
create policy hub_owner_select on public.hub_bills for select to anon, authenticated
    using ((select public.hub_is_owner()));
create policy hub_owner_update on public.hub_bills for update to anon, authenticated
    using ((select public.hub_is_owner())) with check ((select public.hub_is_owner()));

-- Called by the Hub (with the public key) to add or refresh bills.
create or replace function public.hub_push_bills(p_secret text, p_items jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    v_hash text := (select value from public.hub_settings where key = 'push_secret_hash');
    v_n    int := 0;
    r      jsonb;
begin
    if v_hash is null or coalesce(p_secret, '') = ''
       or encode(sha256(convert_to(p_secret, 'utf8')), 'hex') <> v_hash then
        return jsonb_build_object('error', 'forbidden');
    end if;
    if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) > 200 then
        return jsonb_build_object('error', 'bad_items');
    end if;
    for r in select * from jsonb_array_elements(p_items) loop
        continue when coalesce(r ->> 'id', '') = '';
        insert into public.hub_bills (id, sender, summary, urgency, received_at)
        values (left(r ->> 'id', 100), left(r ->> 'sender', 300), left(r ->> 'summary', 500),
                case when r ->> 'urgency' in ('high', 'normal', 'low') then r ->> 'urgency' else 'normal' end,
                coalesce((r ->> 'receivedAt')::timestamptz, now()))
        on conflict (id) do update
            set sender = excluded.sender, summary = excluded.summary, urgency = excluded.urgency;
        v_n := v_n + 1;
    end loop;
    delete from public.hub_bills where received_at < now() - interval '180 days';
    return jsonb_build_object('ok', true, 'count', v_n);
end $$;
revoke execute on function public.hub_push_bills(text, jsonb) from public;
grant execute on function public.hub_push_bills(text, jsonb) to anon;

-- Makes a new push secret, stores only its hash, and shows it once.
create or replace function public.hub_new_push_secret() returns text
language plpgsql security definer set search_path = public as $$
declare v_secret text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
begin
    insert into public.hub_settings (key, value)
    values ('push_secret_hash', encode(sha256(convert_to(v_secret, 'utf8')), 'hex'))
    on conflict (key) do update set value = excluded.value;
    return v_secret;
end $$;
revoke execute on function public.hub_new_push_secret() from public, anon, authenticated;
revoke execute on function public.hub_is_owner() from public;
grant execute on function public.hub_is_owner() to anon, authenticated;
