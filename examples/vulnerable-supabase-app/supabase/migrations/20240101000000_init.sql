-- Deliberately insecure schema: every table below is reachable by anyone who has the project's
-- public anon key (it is embedded in the browser app), so Row Level Security is the only protection.

-- VULNERABLE: RLS is never enabled. Anyone can read, edit and delete every to-do.
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  title text not null,
  done boolean default false
);

-- VULNERABLE: RLS is on, but the policy lets the whole internet read every profile (emails included).
create table public.profiles (
  id uuid primary key references auth.users,
  email text,
  phone text
);
alter table public.profiles enable row level security;
create policy "profiles are public" on public.profiles for select using (true);

-- VULNERABLE: "for all using (true)" is the same as no security at all.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy "everyone can do everything" on public.notes for all using (true) with check (true);

-- VULNERABLE: any signed-in user (anonymous sign-ins included) can edit anyone's row.
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount numeric
);
alter table public.invoices enable row level security;
create policy "signed in can update" on public.invoices for update using (auth.uid() is not null);

-- VULNERABLE: the role comes from user_metadata, which users can change themselves.
create policy "admins read all" on public.invoices for select
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- VULNERABLE: a view runs with its owner's rights and bypasses the RLS of the table it reads.
create view public.invoice_totals as
  select user_id, sum(amount) as total from public.invoices group by user_id;

-- VULNERABLE: SECURITY DEFINER without a pinned search_path, callable through the API.
create function public.make_admin(target uuid) returns void
  language sql security definer
  as $$ update public.profiles set email = email where id = target $$;

-- Safe: RLS on, rows scoped to their owner. Must NOT be flagged.
create table public.projects (
  id bigint generated always as identity primary key,
  owner_id uuid not null,
  name text
);
alter table public.projects enable row level security;
create policy "owner reads" on public.projects for select to authenticated using ((select auth.uid()) = owner_id);
create policy "owner writes" on public.projects for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
