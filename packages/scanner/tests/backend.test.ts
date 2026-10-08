import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath, scanSource } from "../src/index";
import { SupabaseAuthAnalyzer } from "../src/analyzers/supabase-auth";
import { analyzeFirebaseRules, analyzeRealtimeDatabaseRules } from "../src/backend/firebase-rules";
import { splitSql } from "../src/backend/sql";
import { analyzeSupabaseSql } from "../src/backend/supabase-sql";

const sql = (text: string, extra: { file: string; text: string }[] = [], exposedSchemas?: string[]) => {
  const result = analyzeSupabaseSql([{ file: "m1.sql", text }, ...extra], { exposedSchemas });
  return [...result.values()].flat();
};

describe("splitSql", () => {
  it("splits on ; outside comments, strings and dollar-quoted bodies, with line numbers", () => {
    const statements = splitSql(`
      -- a comment; with a semicolon
      create table a (x text default 'a;b');   /* block; comment */
      create function f() returns void as $body$ begin perform 1; perform 2; end; $body$ language plpgsql;
      select 3;`);
    expect(statements.map((s) => s.text.split(" ").slice(0, 3).join(" "))).toEqual(["create table a", "create function f()", "select 3"]);
    expect(statements.map((s) => s.line)).toEqual([3, 4, 5]);
  });
});

describe("supabase-rls: tables", () => {
  it("flags a table in the exposed schema that never gets Row Level Security", () => {
    const found = sql(`create table public.todos (id int primary key, user_id uuid, title text);`);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ ruleId: "supabase-rls", severity: "critical", confidence: "medium" });
    expect(found[0]?.message).toContain("public.todos");
    expect(found[0]?.message).toContain("ENABLE ROW LEVEL SECURITY");
    expect(found[0]?.location.startLine).toBe(1);
  });

  it("is quiet once RLS is enabled, even in a later migration file", () => {
    const created = `create table public.todos (id int, user_id uuid);`;
    expect(sql(created, [{ file: "m2.sql", text: `alter table public.todos enable row level security;` }])).toHaveLength(0);
    expect(sql(`create table todos (id int); alter table only "public"."todos" enable row level security;`)).toHaveLength(0);
  });

  it("flags an explicit DISABLE with high confidence, at the DISABLE line", () => {
    const found = sql(`create table public.t (id int);\nalter table public.t enable row level security;\n\nalter table public.t disable row level security;`);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ confidence: "high" });
    expect(found[0]?.location.startLine).toBe(4);
  });

  it("only looks at schemas the API exposes (public by default, config.toml can add more)", () => {
    expect(sql(`create table private.secrets (id int);`)).toHaveLength(0);
    expect(sql(`create table app.things (id int);`, [], ["public", "app"])).toHaveLength(1);
  });

  it("follows DROP TABLE and RENAME", () => {
    expect(sql(`create table public.a (id int); drop table public.a;`)).toHaveLength(0);
    expect(sql(`create table public.a (id int); alter table public.a rename to b; alter table public.b enable row level security;`)).toHaveLength(0);
  });

  it("is quiet when the table is revoked from the API roles, or the project enables RLS automatically", () => {
    expect(sql(`create table public.a (id int); revoke all on table public.a from anon, authenticated;`)).toHaveLength(0);
    expect(sql(`create table public.a (id int); revoke all on all tables in schema public from anon, authenticated;`)).toHaveLength(0);
    expect(sql(`create function rls_auto_enable() returns event_trigger as $$ begin end; $$ language plpgsql; create event trigger ensure_rls on ddl_command_end execute function rls_auto_enable(); create table public.a (id int);`)).toHaveLength(0);
  });

  it("ignores tool tables and partitions", () => {
    expect(sql(`create table public.schema_migrations (v text); create table public.p partition of public.big for values in (1);`)).toHaveLength(0);
  });
});

describe("supabase-rls: policies", () => {
  const table = `create table public.notes (id int, user_id uuid, body text); alter table public.notes enable row level security;`;

  it("USING (true) for writes: critical for anyone, high for any signed-in user", () => {
    const anyone = sql(`${table} create policy "open" on public.notes for all using (true);`);
    expect(anyone).toHaveLength(1);
    expect(anyone[0]).toMatchObject({ severity: "critical", confidence: "high" });
    expect(anyone[0]?.message).toContain("EVERY row");
    expect(sql(`${table} create policy "p" on public.notes for update to anon using (true) with check (true);`)[0]?.severity).toBe("critical");
    expect(sql(`${table} create policy "p" on public.notes for delete to authenticated using (true);`)[0]?.severity).toBe("high");
  });

  it("unlimited INSERT for anonymous users is high; for signed-in users it is normal", () => {
    expect(sql(`${table} create policy "p" on public.notes for insert to anon with check (true);`)[0]?.severity).toBe("high");
    expect(sql(`${table} create policy "p" on public.notes for insert to authenticated with check (true);`)).toHaveLength(0);
  });

  it("public reads are fine for public data and flagged for personal data", () => {
    expect(sql(`create table public.products (id int, name text); alter table public.products enable row level security; create policy "r" on public.products for select using (true);`)).toHaveLength(0);
    const personal = sql(`create table public.profiles (id uuid, email text); alter table public.profiles enable row level security; create policy "r" on public.profiles for select to anon using (true);`);
    expect(personal).toHaveLength(1);
    expect(personal[0]?.message).toContain("personal data");
  });

  it("'signed in' alone is not ownership for update/delete", () => {
    const found = sql(`${table} create policy "p" on public.notes for update using (auth.uid() is not null);`);
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("signed in");
    expect(sql(`${table} create policy "p" on public.notes for update using ((select auth.role()) = 'authenticated');`)).toHaveLength(1);
    expect(sql(`${table} create policy "p" on public.notes for select using (auth.uid() is not null);`)).toHaveLength(0);
  });

  it("owner-scoped policies are fine", () => {
    expect(sql(`${table} create policy "p" on public.notes for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);`)).toHaveLength(0);
  });

  it("flags access decided from user_metadata (users can edit it themselves)", () => {
    const found = sql(`${table} create policy "admin" on public.notes for all using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');`);
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("app_metadata");
    expect(sql(`${table} create policy "admin" on public.notes for all using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');`)).toHaveLength(0);
  });

  it("DROP POLICY and a later ALTER POLICY change the end state", () => {
    expect(sql(`${table} create policy "open" on public.notes for all using (true); drop policy "open" on public.notes;`)).toHaveLength(0);
    expect(sql(`${table} create policy "p" on public.notes for update using (true); alter policy "p" on public.notes using ((select auth.uid()) = user_id);`)).toHaveLength(0);
  });

  it("storage.objects: a bucket anyone can write to, versus owner-scoped", () => {
    expect(sql(`create policy "up" on storage.objects for insert to anon with check (bucket_id = 'avatars');`)[0]?.severity).toBe("high");
    expect(sql(`create policy "del" on storage.objects for delete to authenticated using (bucket_id = 'avatars');`)[0]?.severity).toBe("medium");
    expect(sql(`create policy "own" on storage.objects for delete to authenticated using (bucket_id = 'avatars' and (select auth.uid()) = owner_id::uuid);`)).toHaveLength(0);
    expect(sql(`create policy "read" on storage.objects for select to anon using (bucket_id = 'avatars');`)).toHaveLength(0);
  });
});

describe("supabase-rls: views and functions", () => {
  const protectedTable = `create table public.orders (id int, user_id uuid); alter table public.orders enable row level security;`;

  it("a view over an RLS table without security_invoker bypasses RLS", () => {
    const found = sql(`${protectedTable} create view public.order_totals as select user_id, count(*) from public.orders group by user_id;`);
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("security_invoker");
    expect(sql(`${protectedTable} create view public.order_totals with (security_invoker = true) as select user_id from public.orders;`)).toHaveLength(0);
    expect(sql(`${protectedTable} create view public.v as select * from public.orders; revoke all on public.v from anon, authenticated;`)).toHaveLength(0);
  });

  it("SECURITY DEFINER without a pinned search_path is flagged; trigger functions and pinned ones are not", () => {
    expect(sql(`create function public.promote(uid uuid) returns void language sql security definer as $$ update profiles set admin = true where id = uid $$;`)).toHaveLength(1);
    expect(sql(`create function public.promote(uid uuid) returns void language sql security definer set search_path = '' as $$ select 1 $$;`)).toHaveLength(0);
    expect(sql(`create function public.on_signup() returns trigger language plpgsql security definer as $$ begin return new; end; $$;`)).toHaveLength(0);
  });

  it("does not read words from inside a function body as options", () => {
    expect(sql(`create function public.f() returns int language sql as $$ select 1 -- security definer is not set here $$;`)).toHaveLength(0);
  });
});

describe("Firestore / Storage rules", () => {
  const now = new Date("2026-06-01T00:00:00Z");
  const fs_ = (body: string) => `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${body}\n  }\n}`;
  const check = (body: string) => analyzeFirebaseRules(fs_(body), "firestore.rules", "firestore", now);

  it("allow read, write: if true is critical", () => {
    const found = check(`    match /{document=**} {\n      allow read, write: if true;\n    }`);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ ruleId: "firebase-rules", severity: "critical", confidence: "high" });
    expect(found[0]?.message).toContain("EVERY document");
    expect(found[0]?.location.startLine).toBe(5);
  });

  it("an `allow` with no condition at all is also open", () => {
    expect(check(`    match /posts/{id} { allow write; }`)[0]?.severity).toBe("critical");
  });

  it("the console's test-mode rule is critical until its date and medium afterwards", () => {
    const open = check(`    match /{document=**} { allow read, write: if request.time < timestamp.date(2099, 1, 1); }`);
    expect(open[0]).toMatchObject({ severity: "critical" });
    expect(open[0]?.message).toContain("test mode");
    const expired = check(`    match /{document=**} { allow read, write: if request.time < timestamp.date(2024, 3, 9); }`);
    expect(expired[0]).toMatchObject({ severity: "medium" });
    expect(expired[0]?.message).toContain("expired");
  });

  it("signed-in-only writes let any user (even anonymous) change anyone's data", () => {
    const found = check(`    match /users/{userId} { allow update, delete: if request.auth != null; }`);
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe("high");
    expect(found[0]?.message).toContain("anonymous");
    expect(check(`    match /{document=**} { allow read, write: if request.auth != null; }`).map((f) => f.severity)).toEqual(["critical"]);
  });

  it("owner checks, helper functions and create-only rules are fine", () => {
    expect(check(`    match /users/{userId} { allow read, write: if request.auth != null && request.auth.uid == userId; }`)).toHaveLength(0);
    expect(check(`    function isOwner(id) { return request.auth.uid == id; }\n    match /notes/{id} { allow write: if isOwner(resource.data.ownerId); }`)).toHaveLength(0);
    expect(check(`    match /posts/{id} { allow create: if request.auth != null; }`)).toHaveLength(0);
  });

  it("public reads: fine for public collections, flagged for private-looking ones", () => {
    expect(check(`    match /products/{id} { allow read: if true; }`)).toHaveLength(0);
    expect(check(`    match /orders/{id} { allow read: if true; }`)[0]?.severity).toBe("high");
    expect(check(`    match /users/{id} { allow read: if request.auth != null; }`)[0]?.severity).toBe("medium");
  });

  it("ignores rules inside comments", () => {
    expect(check(`    // allow read, write: if true;\n    /* allow write: if true; */\n    match /a/{id} { allow read, write: if request.auth.uid == id; }`)).toHaveLength(0);
  });

  it("reads Cloud Storage rules the same way", () => {
    const rules = `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if true;\n    }\n  }\n}`;
    const found = analyzeFirebaseRules(rules, "storage.rules", "storage", now);
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("EVERY file");
    expect(found[0]?.location.startLine).toBe(5);
  });
});

describe("Realtime Database rules", () => {
  const check = (rules: unknown) => analyzeRealtimeDatabaseRules(JSON.stringify({ rules }, null, 2), "database.rules.json");

  it("flags public read/write at the root, and signed-in-only access to the whole database", () => {
    expect(check({ ".read": true, ".write": true }).map((f) => f.severity)).toEqual(["critical", "critical"]);
    expect(check({ ".read": "auth != null", ".write": "auth != null" }).map((f) => f.severity)).toEqual(["high", "high"]);
  });

  it("flags open writes under a path and open reads of private-looking paths", () => {
    const found = check({ users: { $uid: { ".write": true, ".read": true } }, posts: { ".read": true } });
    expect(found.map((f) => `${f.severity}`)).toEqual(["critical", "high"]);
  });

  it("owner-scoped rules are fine", () => {
    expect(check({ users: { $uid: { ".read": "auth != null && auth.uid === $uid", ".write": "$uid === auth.uid" } } })).toHaveLength(0);
  });

  it("reports the line of the offending key", () => {
    const text = `{\n  "rules": {\n    "users": {\n      ".write": true\n    }\n  }\n}`;
    expect(analyzeRealtimeDatabaseRules(text, "d.json")[0]?.location.startLine).toBe(4);
  });

  it("tolerates garbage", () => {
    expect(analyzeRealtimeDatabaseRules("not json", "d.json")).toEqual([]);
    expect(analyzeRealtimeDatabaseRules(`{"foo": 1}`, "d.json")).toEqual([]);
  });
});

describe("supabase-auth (server code)", () => {
  const scan = (source: string, file = "route.ts") => scanSource(source, file, [new SupabaseAuthAnalyzer()]).findings;

  it("flags getSession() on the server", () => {
    const found = scan(`import { createClient } from "@/utils/supabase/server";\nexport async function GET() { const supabase = createClient(); const { data } = await supabase.auth.getSession(); return Response.json(data); }`);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ ruleId: "supabase-auth", severity: "medium" });
    expect(found[0]?.message).toContain("getUser()");
  });

  it("is quiet when the same file verifies with getUser(), or the code runs in the browser", () => {
    expect(scan(`const s = await supabase.auth.getSession(); const u = await supabase.auth.getUser();`)).toHaveLength(0);
    expect(scan(`"use client";\nimport { supabase } from "supabase";\nconst { data } = await supabase.auth.getSession();`)).toHaveLength(0);
    expect(scan(`const { data } = await client.auth.getSession(); // no supabase here`.replace("supabase", "other"))).toHaveLength(0);
  });

  it("flags roles read from user_metadata, not harmless profile fields", () => {
    const found = scan(`// supabase\nconst { data: { user } } = await supabase.auth.getUser();\nif (user.user_metadata.role === "admin") grant();`);
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe("high");
    expect(scan(`// supabase\nconst name = user.user_metadata.full_name; const avatar = user.user_metadata.avatar_url;`)).toHaveLength(0);
    expect(scan(`// supabase\nif (user.app_metadata.role === "admin") grant();`)).toHaveLength(0);
  });
});

describe("scanPath: finding the files", () => {
  let dir: string;
  const write = (rel: string, content: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  };
  const backend = (summary = scanPath(dir)) =>
    summary.results.flatMap((r) => r.findings.map((f) => ({ file: path.relative(dir, r.file).split(path.sep).join("/"), rule: f.ruleId, line: f.location.startLine })));

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-backend-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("analyses supabase/migrations as one timeline", () => {
    write("supabase/migrations/001_init.sql", "create table public.todos (id int, user_id uuid);\n");
    write("supabase/migrations/002_rls.sql", "alter table public.todos enable row level security;\ncreate table public.notes (id int);\n");
    expect(backend()).toEqual([{ file: "supabase/migrations/002_rls.sql", rule: "supabase-rls", line: 2 }]);
  });

  it("ignores SQL that has nothing to do with Supabase", () => {
    write("prisma/migrations/001/migration.sql", "create table public.users (id int);\n");
    write("package.json", JSON.stringify({ dependencies: { prisma: "5" } }));
    expect(backend()).toEqual([]);
  });

  it("analyses any SQL once the project depends on supabase-js, or the SQL uses Supabase functions", () => {
    write("package.json", JSON.stringify({ dependencies: { "@supabase/supabase-js": "2" } }));
    write("db/schema.sql", "create table public.todos (id int);\n");
    expect(backend()).toEqual([{ file: "db/schema.sql", rule: "supabase-rls", line: 1 }]);
    fs.rmSync(path.join(dir, "package.json"));
    expect(backend()).toEqual([]);
    write("db/schema.sql", "create table public.todos (id int);\ncreate policy p on public.todos for select to authenticated using (auth.uid() is not null);\n");
    expect(backend().map((b) => b.rule)).toEqual(["supabase-rls"]);
  });

  it("reads the exposed schemas from supabase/config.toml", () => {
    write("supabase/migrations/001.sql", "create table api.items (id int);\n");
    expect(backend()).toEqual([]);
    write("supabase/config.toml", `[api]\nenabled = true\nschemas = ["public", "api"]\n\n[db]\nport = 54322\n`);
    expect(backend()).toEqual([{ file: "supabase/migrations/001.sql", rule: "supabase-rls", line: 1 }]);
  });

  it("finds firestore.rules, storage.rules and database.rules.json anywhere", () => {
    write("firestore.rules", "service cloud.firestore { match /databases/{d}/documents { match /{document=**} { allow read, write: if true; } } }");
    write("apps/web/storage.rules", "service firebase.storage { match /b/{b}/o { match /{allPaths=**} { allow write: if true; } } }");
    write("apps/web/database.rules.json", `{ "rules": { ".read": true } }`);
    write("docs/example.rules", "this is not a rules file");
    expect(backend().map((b) => `${b.file}:${b.rule}`).sort()).toEqual([
      "apps/web/database.rules.json:firebase-rules",
      "apps/web/storage.rules:firebase-rules",
      "firestore.rules:firebase-rules",
    ]);
  });

  it("honours security-hub-ignore comments (-- in SQL, // in rules) and counts them", () => {
    write("supabase/migrations/001.sql", "-- security-hub-ignore -- public lookup table, reviewed\ncreate table public.countries (code text);\n");
    write("firestore.rules", "service cloud.firestore {\n match /databases/{d}/documents {\n  // security-hub-ignore -- demo project\n  match /{document=**} { allow read, write: if true; }\n }\n}");
    const summary = scanPath(dir);
    expect(summary.findingsCount).toBe(0);
    expect(summary.suppressedCount).toBe(2);
  });

  it("skips ignored folders and counts the files it checked", () => {
    write("node_modules/x/firestore.rules", "service cloud.firestore { match /{document=**} { allow write: if true; } }");
    write("supabase/migrations/001.sql", "create table public.t (id int);\nalter table public.t enable row level security;\n");
    const summary = scanPath(dir);
    expect(summary.filesScanned).toBe(1);
    expect(summary.findingsCount).toBe(0);
  });
});

describe("Firebase service-account keys (and OAuth client secrets) in the repository", () => {
  let dir: string;
  const git = (...args: string[]) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], { cwd: dir, stdio: "pipe", encoding: "utf8" });
  // Assembled at run time so this file holds no key-shaped literal.
  const serviceAccount = () =>
    JSON.stringify(
      {
        type: "service_account",
        project_id: "my-app",
        private_key_id: "0123456789abcdef",
        private_key: "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "\n-----END " + "PRIVATE KEY-----\n",
        client_email: "firebase-adminsdk-abc@my-app.iam.gserviceaccount.com",
      },
      null,
      2,
    );
  const found = () =>
    scanPath(dir).results
      .filter((r) => r.file.endsWith(".json"))
      .flatMap((r) => r.findings);

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-sa-"));
    fs.writeFileSync(path.join(dir, "app.js"), "const a = 1;\n");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("a committed service-account key is critical, and the key itself is never printed", () => {
    git("init", "-q");
    fs.writeFileSync(path.join(dir, "my-app-firebase-adminsdk-abc.json"), serviceAccount());
    git("add", "-A");
    git("commit", "-q", "-m", "oops");
    const findings = found();
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "hardcoded-secret", severity: "critical", confidence: "high" });
    expect(findings[0]?.message).toContain("bypasses every Firestore, Storage and Realtime Database rule");
    expect(findings[0]?.message).toContain("firebase-adminsdk-abc@my-app.iam.gserviceaccount.com");
    expect(findings[0]?.location.startLine).toBe(5);
    expect(JSON.stringify(findings)).not.toContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC");
  });

  it("untracked but not ignored is high; gitignored is the correct setup", () => {
    git("init", "-q");
    fs.writeFileSync(path.join(dir, "serviceAccountKey.json"), serviceAccount());
    expect(found()[0]?.severity).toBe("high");
    fs.writeFileSync(path.join(dir, ".gitignore"), "serviceAccountKey.json\n");
    expect(found()).toHaveLength(0);
  });

  it("flags a downloaded Google OAuth client secret too, and ignores ordinary JSON", () => {
    fs.writeFileSync(path.join(dir, "client_secret_123.apps.googleusercontent.com.json"), JSON.stringify({ web: { client_id: "123.apps", client_secret: "GOCSPX-abcdefghijklmnop" } }));
    fs.writeFileSync(path.join(dir, "credentials.json"), JSON.stringify({ hello: "world" }));
    expect(found()).toHaveLength(1);
  });
});
