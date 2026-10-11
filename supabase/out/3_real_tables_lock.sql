-- Step 2: run only after the new page (the one that logs in through
-- app_login and sends x-app-token) is live. From here on the public key
-- alone can read nothing.

-- PINs are no longer kept readable in users.pin.
create or replace function public.app_users_pin_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    if new.pin is not null and new.pin <> '' then
        insert into public.app_secrets (user_id, pin_hash)
        values (new.user_id, public.app_hash(new.user_id, new.pin))
        on conflict (user_id) do update set pin_hash = excluded.pin_hash, updated_at = now();
    end if;
    new.pin := null;
    return new;
end $$;

update public.users set pin = null where pin is not null;

alter table public.users      enable row level security;
alter table public.month_data enable row level security;
alter table public.feedback   enable row level security;
alter table public.group_chat enable row level security;
