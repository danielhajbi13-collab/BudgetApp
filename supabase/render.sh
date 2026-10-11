#!/bin/sh
# Renders the templates into out/, in the order they are run in the
# Supabase SQL editor:
#   1_test_tables.sql          throw-away copies (stg_*) with the new rules, to test against
#   2_real_tables_prepare.sql  the real tables: adds everything, row-level security still off
#   3_real_tables_lock.sql     the real tables: switches row-level security on (new page must be live)
#   4_remove_test_tables.sql   drops the stg_* copies
mkdir -p out
r() { sed "s/{{P}}/$1/g" "$2.template.sql"; }
{
  for t in users month_data feedback group_chat; do
    echo "create table if not exists public.stg_$t (like public.$t including all);"
  done
  echo "grant select, insert, update, delete on public.stg_users, public.stg_month_data, public.stg_feedback, public.stg_group_chat to anon, authenticated;"
  r stg_ secure_access; r stg_ enable_rls
} > out/1_test_tables.sql
r "" secure_access > out/2_real_tables_prepare.sql
r "" enable_rls > out/3_real_tables_lock.sql
