-- DUKUN CHEAT Premium activation schema
-- Run this once in the SQL Editor of a NEW Supabase project.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.activation_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  redeemed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.premium_licenses (
  id uuid primary key default gen_random_uuid(),
  activation_code_id uuid not null unique references public.activation_codes(id),
  token_hash text not null unique,
  activated_at timestamptz not null default now(),
  revoked_at timestamptz
);

alter table public.activation_codes enable row level security;
alter table public.premium_licenses enable row level security;

-- No public/anon/authenticated policies. Access is only through the Edge Function
-- using the server-side service-role key.

create or replace function public.generate_dukun_activation_codes(p_count integer default 10)
returns table(activation_code text)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  i integer;
  raw_code text;
begin
  if p_count < 1 or p_count > 500 then
    raise exception 'Jumlah kode harus antara 1 sampai 500';
  end if;

  for i in 1..p_count loop
    raw_code := upper(encode(extensions.gen_random_bytes(8), 'hex'));
    insert into public.activation_codes(code_hash)
    values (encode(extensions.digest(raw_code, 'sha256'), 'hex'));
    activation_code := raw_code;
    return next;
  end loop;
end;
$$;

revoke all on function public.generate_dukun_activation_codes(integer) from public, anon, authenticated;
grant execute on function public.generate_dukun_activation_codes(integer) to postgres, service_role;
