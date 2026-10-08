# Deliberately insecure Supabase app

Scanner test fixture. **Never deploy this.** Run the scanner against it:

```bash
npm run scan -- scan examples/vulnerable-supabase-app --format text
```

| Where | What the scanner should say |
|---|---|
| `supabase/migrations/..._init.sql`, `public.todos` | Row Level Security never enabled (critical) |
| `public.profiles` | `USING (true)` lets anyone read emails and phone numbers |
| `public.notes` | `FOR ALL USING (true)`: no security at all (critical) |
| `public.invoices` | "signed in" is not ownership for UPDATE; a role decided from `user_metadata` |
| `public.invoice_totals` | view without `security_invoker` bypasses RLS |
| `public.make_admin` | `SECURITY DEFINER` without `search_path` |
| `public.projects` | **Safe** (owner-scoped policies): must not be flagged |
| `app/api/admin/route.ts` | `getSession()` on the server, and a role read from `user_metadata` |
