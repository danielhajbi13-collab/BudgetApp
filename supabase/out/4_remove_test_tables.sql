drop table if exists public.stg_users, public.stg_month_data, public.stg_feedback, public.stg_group_chat,
    public.stg_app_secrets, public.stg_app_sessions, public.stg_app_login_attempts cascade;
do $$
declare r record;
begin
    for r in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
             where n.nspname = 'public' and p.proname like 'stg\_app\_%' loop
        execute 'drop function ' || r.sig || ' cascade';
    end loop;
end $$;
