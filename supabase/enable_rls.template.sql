-- Step 2: run only after the new page (the one that logs in through
-- app_login and sends x-app-token) is live. From here on the public key
-- alone can read nothing.

-- PINs are no longer kept readable in users.pin.
create or replace function public.{{P}}app_users_pin_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    if new.pin is not null and new.pin <> '' then
        insert into public.{{P}}app_secrets (user_id, pin_hash)
        values (new.user_id, public.{{P}}app_hash(new.user_id, new.pin))
        on conflict (user_id) do update set pin_hash = excluded.pin_hash, updated_at = now();
    end if;
    new.pin := null;
    return new;
end $$;

update public.{{P}}users set pin = null where pin is not null;

alter table public.{{P}}users      enable row level security;
alter table public.{{P}}month_data enable row level security;
alter table public.{{P}}feedback   enable row level security;
alter table public.{{P}}group_chat enable row level security;
