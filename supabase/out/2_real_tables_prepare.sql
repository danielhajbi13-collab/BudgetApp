-- Secure access for BudgetApp.
--
-- The app has its own ID + PIN login and talks to the tables straight from
-- the browser, so until now every table had to be open to the public key:
-- anyone could read, change or delete every user's phone, email, PIN and
-- budget. This script moves the PIN check into the database and ties each
-- request to a login session:
--
--   * app_login / app_register / app_recover_* check the PIN on the server
--     and hand back a random session token.
--   * The browser sends that token in the "x-app-token" header on every
--     request; the row-level-security policies below use it to decide which
--     rows the caller may touch.
--   * PINs live (hashed) in app_secrets, which the public key cannot read.
--
-- Step 1 (this file) is safe to run while the old page is still live: it
-- adds everything but leaves row-level security switched off. Step 2
-- (enable_rls) flips it on once the new page is deployed.
--
--  is a table/function prefix: empty for the real tables, "stg_" for
-- the throw-away copies used to test this end to end (see render.sh).

-- ---------------------------------------------------------------- tables
create table if not exists public.app_secrets (
    user_id    text primary key,
    pin_hash   text not null,
    updated_at timestamptz not null default now()
);
create table if not exists public.app_sessions (
    token_hash text primary key,
    user_id    text,                      -- null for the super admin
    is_admin   boolean not null default false,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
create table if not exists public.app_login_attempts (
    id      bigint generated always as identity primary key,
    user_id text not null,
    at      timestamptz not null default now()
);
create index if not exists app_login_attempts_idx on public.app_login_attempts (user_id, at);

alter table public.app_secrets        enable row level security;
alter table public.app_sessions       enable row level security;
alter table public.app_login_attempts enable row level security;
revoke all on public.app_secrets, public.app_sessions, public.app_login_attempts from anon, authenticated;

-- --------------------------------------------------------------- helpers
create or replace function public.app_hash(p_user text, p_pin text) returns text
language sql immutable as $$
    select encode(sha256(convert_to(p_user || ':' || p_pin, 'utf8')), 'hex')
$$;

create or replace function public.app_session() returns public.app_sessions
language sql stable security definer set search_path = public as $$
    select s.* from public.app_sessions s
    where s.token_hash = encode(sha256(convert_to(coalesce(
              nullif(current_setting('request.headers', true), '')::json ->> 'x-app-token', ''), 'utf8')), 'hex')
      and s.expires_at > now()
    limit 1
$$;

create or replace function public.app_uid() returns text
language sql stable security definer set search_path = public as $$
    select (public.app_session()).user_id
$$;

create or replace function public.app_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
    select coalesce((public.app_session()).is_admin, false)
$$;

-- The group this caller manages / belongs to (null when none).
create or replace function public.app_my_mgr_code() returns text
language sql stable security definer set search_path = public as $$
    select u.manager_code from public.users u where u.user_id = public.app_uid()
$$;

create or replace function public.app_my_group() returns text
language sql stable security definer set search_path = public as $$
    select u.group_code from public.users u where u.user_id = public.app_uid()
$$;

-- Is p_user a member of the group this caller manages?
create or replace function public.app_manages(p_user text) returns boolean
language sql stable security definer set search_path = public as $$
    select exists (
        select 1 from public.users u
        where u.user_id = p_user and u.group_code is not null
          and u.group_code = public.app_my_mgr_code())
$$;

create or replace function public.app_new_session(p_user text, p_admin boolean) returns text
language plpgsql security definer set search_path = public as $$
declare v_token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
begin
    delete from public.app_sessions where expires_at < now();
    insert into public.app_sessions (token_hash, user_id, is_admin, expires_at)
    values (encode(sha256(convert_to(v_token, 'utf8')), 'hex'), p_user, p_admin, now() + interval '90 days');
    return v_token;
end $$;

-- Too many wrong PINs for one ID within 15 minutes locks that ID out.
create or replace function public.app_locked_out(p_id text) returns boolean
language sql stable security definer set search_path = public as $$
    select count(*) >= 8 from public.app_login_attempts
    where user_id = p_id and at > now() - interval '15 minutes'
$$;

create or replace function public.app_phone_matches(p_stored text, p_input text) returns boolean
language sql immutable as $$
    select coalesce(p_stored, '') <> '' and (
        p_input = p_stored
        or (case when p_input like '0%' then '+972' || substr(p_input, 2) else p_input end) = p_stored)
$$;

revoke execute on function public.app_new_session(text, boolean), public.app_locked_out(text),
    public.app_hash(text, text), public.app_phone_matches(text, text) from public, anon, authenticated;

-- ------------------------------------------------- functions the page calls
create or replace function public.app_login(p_id text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    v_admin jsonb;
    v_user  public.users;
begin
    p_id := btrim(coalesce(p_id, '')); p_pin := btrim(coalesce(p_pin, ''));
    if p_id = '' or p_pin = '' then return jsonb_build_object('error', 'bad_request'); end if;
    if public.app_locked_out(p_id) then return jsonb_build_object('error', 'too_many'); end if;

    -- The super admin's login lives in a special month_data row (the page
    -- lets the admin change it); 000000000/0000 until it is first changed.
    select m.data into v_admin from public.month_data m
    where m.user_id = '__super_admin__' and m.month_str = '__admin_credentials__';
    if coalesce(v_admin ->> 'id', '') = '' or coalesce(v_admin ->> 'pin', '') = '' then
        v_admin := jsonb_build_object('id', '000000000', 'pin', '0000');
    end if;
    if p_id = v_admin ->> 'id' and p_pin = v_admin ->> 'pin' then
        return jsonb_build_object('kind', 'admin', 'token', public.app_new_session(null, true));
    end if;

    select * into v_user from public.users u where u.user_id = p_id;
    if not found then
        if p_id = v_admin ->> 'id' then
            insert into public.app_login_attempts (user_id) values (p_id);
            return jsonb_build_object('error', 'bad_pin');
        end if;
        return jsonb_build_object('error', 'no_user');
    end if;
    if exists (select 1 from public.app_secrets s
               where s.user_id = p_id and s.pin_hash = public.app_hash(p_id, p_pin)) then
        return jsonb_build_object('kind', 'user', 'token', public.app_new_session(p_id, false),
                                  'user', to_jsonb(v_user) - 'pin');
    end if;
    insert into public.app_login_attempts (user_id) values (p_id);
    return jsonb_build_object('error', 'bad_pin');
end $$;

-- Who does the token in this request belong to? Used when the page reloads.
create or replace function public.app_whoami() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_s public.app_sessions := public.app_session();
begin
    if v_s.token_hash is null then return jsonb_build_object('kind', null); end if;
    if v_s.is_admin then return jsonb_build_object('kind', 'admin'); end if;
    return (select jsonb_build_object('kind', 'user', 'user', to_jsonb(u) - 'pin')
            from public.users u where u.user_id = v_s.user_id);
end $$;

create or replace function public.app_logout() returns void
language sql security definer set search_path = public as $$
    delete from public.app_sessions where token_hash = (public.app_session()).token_hash
$$;

create or replace function public.app_group_by_code(p_code text) returns jsonb
language sql stable security definer set search_path = public as $$
    select jsonb_build_object('username', u.username, 'group_code', u.manager_code,
        'group_name', u.manager_group_name, 'avatar', u.manager_group_avatar, 'desc', u.manager_group_desc)
    from public.users u
    where coalesce(p_code, '') <> '' and u.manager_code = p_code
    limit 1
$$;

create or replace function public.app_register(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    v_id    text := btrim(coalesce(p ->> 'user_id', ''));
    v_pin   text := btrim(coalesce(p ->> 'pin', ''));
    v_code  text := nullif(upper(btrim(coalesce(p ->> 'group_code', ''))), '');
    v_gname text;
    v_user  public.users;
begin
    if v_id !~ '^[0-9]{5,9}$' then return jsonb_build_object('error', 'bad_id'); end if;
    if length(v_pin) <> 4 then return jsonb_build_object('error', 'bad_pin_format'); end if;
    if btrim(coalesce(p ->> 'username', '')) = '' or btrim(coalesce(p ->> 'phone', '')) = '' then
        return jsonb_build_object('error', 'missing_fields');
    end if;
    if exists (select 1 from public.users u where u.user_id = v_id) then
        return jsonb_build_object('error', 'exists');
    end if;
    if v_code is not null then
        select u.manager_group_name into v_gname from public.users u where u.manager_code = v_code limit 1;
        if not found then return jsonb_build_object('error', 'bad_group'); end if;
    end if;
    insert into public.users (user_id, username, email, phone, pin, is_pro, role, group_code, group_name)
    values (v_id, btrim(p ->> 'username'), coalesce(p ->> 'email', ''), btrim(p ->> 'phone'), v_pin,
            'true', 'user', v_code, nullif(coalesce(v_gname, ''), ''))
    returning * into v_user;
    return jsonb_build_object('kind', 'user', 'token', public.app_new_session(v_id, false),
                              'user', to_jsonb(v_user) - 'pin');
end $$;

-- Forgotten PIN: the caller proves themselves with the phone on file.
create or replace function public.app_recover_check(p_id text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_user public.users;
begin
    p_id := btrim(coalesce(p_id, '')); p_phone := btrim(coalesce(p_phone, ''));
    if public.app_locked_out(p_id) then return jsonb_build_object('error', 'too_many'); end if;
    select * into v_user from public.users u where u.user_id = p_id;
    if not found then return jsonb_build_object('error', 'no_user'); end if;
    if not public.app_phone_matches(v_user.phone, p_phone) then
        insert into public.app_login_attempts (user_id) values (p_id);
        return jsonb_build_object('error', 'mismatch');
    end if;
    return jsonb_build_object('ok', true, 'username', v_user.username);
end $$;

create or replace function public.app_recover_reset(p_id text, p_phone text, p_new_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_check jsonb := public.app_recover_check(p_id, p_phone);
        v_user  public.users;
begin
    if v_check ? 'error' then return v_check; end if;
    p_id := btrim(p_id); p_new_pin := btrim(coalesce(p_new_pin, ''));
    if length(p_new_pin) <> 4 then return jsonb_build_object('error', 'bad_pin_format'); end if;
    update public.users set pin = p_new_pin where user_id = p_id returning * into v_user;
    delete from public.app_sessions where user_id = p_id;
    return jsonb_build_object('kind', 'user', 'token', public.app_new_session(p_id, false),
                              'user', to_jsonb(v_user) - 'pin');
end $$;

-- A manager (or the super admin, acting on a group) adds or removes a member.
create or replace function public.app_manager_add_member(p_code text, p_member text, p_force boolean default false)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_mgr public.users; v_user public.users;
begin
    if coalesce(p_code, '') = '' or not (public.app_is_admin() or coalesce(public.app_my_mgr_code() = p_code, false)) then
        return jsonb_build_object('status', 'forbidden');
    end if;
    select * into v_mgr from public.users u where u.manager_code = p_code limit 1;
    select * into v_user from public.users u where u.user_id = btrim(coalesce(p_member, ''));
    if not found then return jsonb_build_object('status', 'not_found'); end if;
    if v_user.user_id = v_mgr.user_id then return jsonb_build_object('status', 'self'); end if;
    if v_user.group_code = p_code then return jsonb_build_object('status', 'already'); end if;
    if v_user.group_code is not null and v_user.group_code <> '' and not coalesce(p_force, false) then
        return jsonb_build_object('status', 'other_group');
    end if;
    update public.users set group_code = p_code, group_name = coalesce(v_mgr.manager_group_name, '')
    where user_id = v_user.user_id;
    return jsonb_build_object('status', 'ok', 'username', v_user.username);
end $$;

create or replace function public.app_manager_remove_member(p_code text, p_member text)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
    if coalesce(p_code, '') = '' or not (public.app_is_admin() or coalesce(public.app_my_mgr_code() = p_code, false)) then
        return jsonb_build_object('status', 'forbidden');
    end if;
    update public.users set group_code = null, group_name = null
    where user_id = p_member and group_code = p_code;
    return jsonb_build_object('status', 'ok');
end $$;

-- -------------------------------------------------------------- triggers
-- Any PIN written to users.pin (signup, profile update, admin creating a
-- manager) is copied, hashed, into app_secrets. Step 2 replaces this
-- function with one that also blanks users.pin.
create or replace function public.app_users_pin_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    if new.pin is not null and new.pin <> '' then
        insert into public.app_secrets (user_id, pin_hash)
        values (new.user_id, public.app_hash(new.user_id, new.pin))
        on conflict (user_id) do update set pin_hash = excluded.pin_hash, updated_at = now();
    end if;
    return new;
end $$;
drop trigger if exists app_users_pin on public.users;
create trigger app_users_pin before insert or update on public.users
    for each row execute function public.app_users_pin_trg();

-- A user may edit their own profile but not promote themselves: only the
-- super admin changes the ID, role, pro flag or manager code. Server-side
-- functions above (which run as the owner) are not restricted.
create or replace function public.app_users_guard_trg() returns trigger
language plpgsql set search_path = public as $$
begin
    if current_user in ('anon', 'authenticated') and not public.app_is_admin() then
        if new.user_id is distinct from old.user_id or new.role is distinct from old.role
           or new.is_pro is distinct from old.is_pro or new.manager_code is distinct from old.manager_code then
            raise exception 'not allowed to change this field';
        end if;
    end if;
    return new;
end $$;
drop trigger if exists app_users_guard on public.users;
create trigger app_users_guard before update on public.users
    for each row execute function public.app_users_guard_trg();

create or replace function public.app_users_cleanup_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    delete from public.app_secrets  where user_id = old.user_id;
    delete from public.app_sessions where user_id = old.user_id;
    return old;
end $$;
drop trigger if exists app_users_cleanup on public.users;
create trigger app_users_cleanup after delete on public.users
    for each row execute function public.app_users_cleanup_trg();

-- Existing PINs -> app_secrets.
insert into public.app_secrets (user_id, pin_hash)
select u.user_id, public.app_hash(u.user_id, u.pin) from public.users u
where u.pin is not null and u.pin <> ''
on conflict (user_id) do update set pin_hash = excluded.pin_hash, updated_at = now();

-- -------------------------------------------------------------- policies
-- The old policies all tested Supabase Auth's auth.uid(), which this app
-- never uses, so they matched nobody (or, on feedback, everybody).
do $$
declare r record;
begin
    for r in select policyname, tablename from pg_policies
             where schemaname = 'public'
               and tablename in ('users', 'month_data', 'feedback', 'group_chat') loop
        execute format('drop policy %I on public.%I', r.policyname, r.tablename);
    end loop;
end $$;

-- feedback was the one table with row-level security already on (with
-- policies that let everyone do everything). Until step 2 switches all four
-- tables on together it has to stay reachable for the page that is live now.
alter table public.feedback disable row level security;

-- users: yourself; the super admin; a manager sees the members of their group.
create policy app_select on public.users for select to anon, authenticated using (
    (select public.app_is_admin()) or user_id = (select public.app_uid())
    or group_code = (select public.app_my_mgr_code()));
create policy app_insert on public.users for insert to anon, authenticated
    with check ((select public.app_is_admin()));
create policy app_update on public.users for update to anon, authenticated
    using      ((select public.app_is_admin()) or user_id = (select public.app_uid()))
    with check ((select public.app_is_admin()) or user_id = (select public.app_uid()));
create policy app_delete on public.users for delete to anon, authenticated
    using ((select public.app_is_admin()) or user_id = (select public.app_uid()));

-- month_data: your own rows; the super admin; a manager working inside a
-- member's account. The admin-credentials row belongs to no user, so only
-- the super admin reaches it.
create policy app_all on public.month_data for all to anon, authenticated
    using      ((select public.app_is_admin()) or user_id = (select public.app_uid())
                or public.app_manages(user_id))
    with check ((select public.app_is_admin()) or user_id = (select public.app_uid())
                or public.app_manages(user_id));

-- feedback: your own threads; the super admin; a manager sees and answers
-- what was addressed to their group.
create policy app_select on public.feedback for select to anon, authenticated using (
    (select public.app_is_admin()) or user_id = (select public.app_uid())
    or (target = 'manager' and group_code = (select public.app_my_mgr_code())));
create policy app_insert on public.feedback for insert to anon, authenticated with check (
    (select public.app_is_admin()) or user_id = (select public.app_uid())
    or (target = 'manager' and group_code = (select public.app_my_mgr_code())));
create policy app_update on public.feedback for update to anon, authenticated
    using ((select public.app_is_admin()) or user_id = (select public.app_uid())
           or (target = 'manager' and group_code = (select public.app_my_mgr_code())))
    with check ((select public.app_is_admin()) or user_id = (select public.app_uid())
           or (target = 'manager' and group_code = (select public.app_my_mgr_code())));
create policy app_delete on public.feedback for delete to anon, authenticated
    using ((select public.app_is_admin()));

-- group_chat: the group you belong to or manage; '__ADMINS__' is the
-- managers' chat with the super admin.
create policy app_select on public.group_chat for select to anon, authenticated using (
    (select public.app_is_admin())
    or group_code = (select public.app_my_group())
    or group_code = (select public.app_my_mgr_code())
    or (group_code = '__ADMINS__' and (select public.app_my_mgr_code()) is not null));
create policy app_insert on public.group_chat for insert to anon, authenticated with check (
    (select public.app_is_admin())
    or (user_id = (select public.app_uid()) and (
            group_code = (select public.app_my_group())
         or group_code = (select public.app_my_mgr_code())
         or (group_code = '__ADMINS__' and (select public.app_my_mgr_code()) is not null))));
create policy app_delete on public.group_chat for delete to anon, authenticated
    using ((select public.app_is_admin()));

revoke truncate, references, trigger on public.users, public.month_data,
    public.feedback, public.group_chat from anon, authenticated;
