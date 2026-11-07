-- Sigma E Manager database schema (already applied to the sigma-e Supabase project)

-- ===== Tables =====
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  name text not null default 'New member',
  role text not null default 'member' check (role in ('admin','leader','member')),
  team text check (team in ('fusion','flux')),
  avatar_url text,
  created_at timestamptz default now()
);

create table public.tasks (
  id bigint generated always as identity primary key,
  title text not null,
  team text not null check (team in ('fusion','flux')),
  status text not null default 'todo' check (status in ('todo','doing','done')),
  due date,
  assignees uuid[] not null default '{}',
  created_by uuid references public.profiles on delete set null default auth.uid(),
  created_at timestamptz default now()
);

-- ===== Helpers =====
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public
as $$ select role from profiles where id = auth.uid() $$;

create or replace function public.my_team() returns text
language sql stable security definer set search_path = public
as $$ select team from profiles where id = auth.uid() $$;

-- New sign-up -> profile. The very first person becomes admin.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  insert into profiles (id, name, role)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)),
          case when exists (select 1 from profiles) then 'member' else 'admin' end);
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- Only admins can change someone's role or team
create or replace function public.guard_profile() returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if public.my_role() is distinct from 'admin'
     and (new.role is distinct from old.role or new.team is distinct from old.team) then
    raise exception 'Only admins can change role or team';
  end if;
  return new;
end $$;

create trigger guard_profile before update on public.profiles
for each row execute function public.guard_profile();

-- Members may only change the status of tasks assigned to them
create or replace function public.guard_task() returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if public.my_role() = 'admin' or (public.my_role() = 'leader' and public.my_team() = old.team and public.my_team() = new.team) then
    return new;
  end if;
  if new.title is distinct from old.title or new.team is distinct from old.team
     or new.due is distinct from old.due or new.assignees is distinct from old.assignees then
    raise exception 'Members can only change task status';
  end if;
  return new;
end $$;

create trigger guard_task before update on public.tasks
for each row execute function public.guard_task();

-- ===== Row Level Security =====
alter table public.profiles enable row level security;
alter table public.tasks enable row level security;

create policy "read profiles" on public.profiles for select to authenticated using (true);
create policy "edit own or admin" on public.profiles for update to authenticated
  using (id = auth.uid() or public.my_role() = 'admin');
create policy "admin deletes" on public.profiles for delete to authenticated
  using (public.my_role() = 'admin');

create policy "read tasks" on public.tasks for select to authenticated using (true);
create policy "create tasks" on public.tasks for insert to authenticated
  with check (public.my_role() = 'admin' or (public.my_role() = 'leader' and team = public.my_team()));
create policy "update tasks" on public.tasks for update to authenticated
  using (public.my_role() = 'admin'
      or (public.my_role() = 'leader' and team = public.my_team())
      or auth.uid() = any(assignees));
create policy "delete tasks" on public.tasks for delete to authenticated
  using (public.my_role() = 'admin' or (public.my_role() = 'leader' and team = public.my_team()));

-- ===== Profile photos =====
insert into storage.buckets (id, name, public) values ('avatars','avatars', true)
on conflict (id) do nothing;

create policy "avatar upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar update" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar read" on storage.objects for select using (bucket_id = 'avatars');
