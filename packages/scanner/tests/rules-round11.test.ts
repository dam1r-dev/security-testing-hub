import { scanSource, RULE_IDS } from "../src";

const ruleFindings = (code: string, rule: string, file = "/app/src/handler.ts"): string[] =>
  scanSource(code, file).findings.filter((f) => f.ruleId === rule).map((f) => f.sinkSnippet);

describe("mass-assignment", () => {
  const rule = "mass-assignment";

  it("flags the whole body going into a database write, in every ORM's style", () => {
    expect(ruleFindings("app.post('/signup', async (req, res) => { const user = await User.create(req.body); res.json(user); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.put('/me', async (req, res) => { await prisma.user.update({ where: { id: 1 }, data: req.body }); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/x', async (req, res) => { const u = new User(req.body); await u.save(); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.put('/x', async (req, res) => { await User.findByIdAndUpdate(req.params.id, req.body); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/x', async (req, res) => { await prisma.post.create({ data: { ...req.body, authorId: 1 } }); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/x', async (req, res) => { Object.assign(user, req.body); await user.save(); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.put('/x', async (req, res) => { const { error } = await supabase.from('profiles').update(req.body).eq('id', 1); });", rule)).toHaveLength(1);
  });

  it("follows the body through a variable and through the Web Request / h3 / Hono readers", () => {
    expect(ruleFindings("export async function POST(request: Request) { const body = await request.json(); await prisma.user.create({ data: body }); }", rule)).toHaveLength(1);
    expect(ruleFindings("export default defineEventHandler(async (event) => { const data = await readBody(event); await db.order.create({ data }); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/x', async (c) => { const b = await c.req.json(); await db.insert(users).values(b); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/x', async (req, res) => { const input = req.body; const copy = { ...input }; await User.create(copy); });", rule)).toHaveLength(1);
  });

  it("does not flag picked fields, a validated body, a stripped body or a filter", () => {
    expect(ruleFindings("app.post('/x', async (req, res) => { const { name, email } = req.body; await User.create({ name, email }); });", rule)).toHaveLength(0);
    expect(ruleFindings("app.post('/x', async (req, res) => { await User.create({ name: req.body.name }); });", rule)).toHaveLength(0);
    expect(ruleFindings("app.post('/x', async (req, res) => { const data = schema.parse(req.body); await prisma.user.create({ data }); });", rule)).toHaveLength(0);
    expect(ruleFindings("app.post('/x', async (req, res) => { delete req.body.role; await User.create(req.body); });", rule)).toHaveLength(0);
    expect(ruleFindings("app.get('/x', async (req, res) => { res.json(await prisma.user.findMany({ where: req.body })); });", rule)).toHaveLength(0);
    expect(ruleFindings("app.post('/x', (req, res) => { res.json(Object.assign({}, req.body)); });", rule)).toHaveLength(0); // a copy for the response, not a write
  });
});

describe("prototype-pollution", () => {
  const rule = "prototype-pollution";

  it("flags request data deep-merged into an object, or used as the keys of a nested assignment", () => {
    expect(ruleFindings("const _ = require('lodash');\napp.post('/s', (req, res) => { _.merge(settings, req.body); });", rule)).toHaveLength(1);
    expect(ruleFindings("import merge from 'deepmerge';\napp.post('/s', (req, res) => { const m = merge(defaults, req.body); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/s', (req, res) => { _.set(obj, req.body.path, req.body.value); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/s', (req, res) => { prefs[req.body.group][req.body.key] = req.body.value; });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/s', (req, res) => { $.extend(true, {}, req.body); });", rule)).toHaveLength(1);
  });

  it("does not flag shallow copies, a project's own merge helper, fixed keys or one-level assignment", () => {
    expect(ruleFindings("app.post('/s', (req, res) => { Object.assign(settings, req.body); });", rule)).toHaveLength(0);
    expect(ruleFindings("function merge(a, b) { return { ...a, ...b }; }\napp.post('/s', (req, res) => { merge(settings, req.body); });", rule)).toHaveLength(0);
    expect(ruleFindings("app.post('/s', (req, res) => { prefs.theme.color = req.body.color; prefs['a']['b'] = req.body.v; });", rule)).toHaveLength(0);
    expect(ruleFindings("app.post('/s', (req, res) => { counts[req.body.key] = 1; });", rule)).toHaveLength(0);
  });
});

describe("webhook-signature", () => {
  const rule = "webhook-signature";
  const STRIPE_HANDLER = (verify: string): string =>
    `export async function POST(request: Request) {\n  const raw = await request.text();\n  ${verify}\n  const event = JSON.parse(raw);\n  if (event.type === 'checkout.session.completed') { await grantPlan(event); }\n  return new Response('ok');\n}\n`;

  it("flags a Stripe handler that trusts the body, and says what to call", () => {
    const [finding] = scanSource(STRIPE_HANDLER(""), "/app/api/stripe/route.ts").findings.filter((f) => f.ruleId === rule);
    expect(finding?.severity).toBe("high");
    expect(finding?.message).toContain("constructEvent");
    expect(finding?.location.startLine).toBe(5);
    expect(ruleFindings("app.post('/hook', async (req, res) => { if (req.body.type === 'payment_intent.succeeded') { await fulfil(req.body); } res.sendStatus(200); });", rule)).toHaveLength(1);
    expect(ruleFindings("app.post('/ls', (req, res) => { if (req.body.meta.event_name === 'order_created') { grant(); } res.end(); });", rule)).toHaveLength(1);
  });

  it("is quiet when the handler verifies: constructEvent, a signature header, svix, an HMAC, a verify helper", () => {
    expect(ruleFindings(STRIPE_HANDLER("const e = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature')!, secret);"), rule)).toHaveLength(0);
    expect(ruleFindings(STRIPE_HANDLER("await verifyStripeWebhook(request, raw);"), rule)).toHaveLength(0);
    expect(ruleFindings(STRIPE_HANDLER("const ok = crypto.timingSafeEqual(a, b);"), rule)).toHaveLength(0);
  });

  it("a comment saying 'no signature' is not a check, and a file that only lists event names is not a handler", () => {
    expect(ruleFindings(STRIPE_HANDLER("// TODO: check the signature"), rule)).toHaveLength(1);
    expect(ruleFindings("export const EVENTS = ['checkout.session.completed', 'invoice.paid'];\n", rule)).toHaveLength(0);
    expect(ruleFindings("// handles 'checkout.session.completed'\nexport async function POST() { return new Response('ok'); }\n", rule)).toHaveLength(0);
  });
});

describe("insecure-token-storage", () => {
  const rule = "insecure-token-storage";

  it("flags a login token kept in browser storage or in a cookie written from JavaScript", () => {
    expect(ruleFindings("localStorage.setItem('token', res.token);", rule, "/app/src/auth.ts")).toHaveLength(1);
    expect(ruleFindings("sessionStorage.setItem('access_token', t); localStorage.setItem(\"jwt\", j);", rule, "/app/src/auth.ts")).toHaveLength(2);
    expect(ruleFindings("window.localStorage.authToken = t;", rule, "/app/src/auth.ts")).toHaveLength(1);
    expect(ruleFindings("localStorage['refresh_token'] = r;", rule, "/app/src/auth.ts")).toHaveLength(1);
    expect(ruleFindings("document.cookie = 'token=' + jwt + '; path=/';", rule, "/app/src/auth.ts")).toHaveLength(1);
    expect(ruleFindings("import Cookies from 'js-cookie';\nCookies.set('session_token', t);", rule, "/app/src/auth.ts")).toHaveLength(1);
  });

  it("does not flag UI state, a CSRF token that is meant for scripts, or a flag about a token", () => {
    expect(ruleFindings("localStorage.setItem('theme', 'dark'); localStorage.setItem('authMode', 'login'); localStorage.setItem('lang', 'ru');", rule, "/app/src/ui.ts")).toHaveLength(0);
    expect(ruleFindings("localStorage.setItem('csrfToken', t); localStorage.setItem('hasToken', '1');", rule, "/app/src/ui.ts")).toHaveLength(0);
    expect(ruleFindings("const t = localStorage.getItem('token');", rule, "/app/src/ui.ts")).toHaveLength(0); // reading is the other half, not the mistake
    expect(ruleFindings("document.cookie = 'theme=dark';", rule, "/app/src/ui.ts")).toHaveLength(0);
  });
});

describe("rule ids", () => {
  it("the four new rules are known to the ignore list and the settings file", () => {
    for (const id of ["mass-assignment", "prototype-pollution", "webhook-signature", "insecure-token-storage"]) expect(RULE_IDS).toContain(id);
    expect(RULE_IDS).toHaveLength(29);
  });

  it("// security-hub-ignore works for them", () => {
    const code = "app.post('/signup', async (req, res) => {\n  // security-hub-ignore mass-assignment -- the model has no privileged fields\n  await User.create(req.body);\n});\n";
    const result = scanSource(code, "/app/signup.ts");
    expect(result.findings.filter((f) => f.ruleId === "mass-assignment")).toHaveLength(0);
    expect(result.suppressed).toBe(1);
  });
});

// Precision fixes found by validation round 11 (docs/validation.md): each of these was a false positive on a real project.
describe("round 11 precision fixes", () => {
  const rules = (code: string, file = "/app/src/handler.ts"): string[] => scanSource(code, file).findings.map((f) => f.ruleId);

  it("SSRF: a URL whose scheme and host are written in the code only lets the caller choose the path", () => {
    expect(rules("export const GET = ({ params }) => fetch(`https://oeis.org/${params.anumber}?fmt=json`);\n")).not.toContain("ssrf");
    expect(rules("app.get('/x', (req, res) => { fetch('https://api.example.com/items/' + req.query.id); });")).not.toContain("ssrf");
    // the host itself is attacker-chosen: still SSRF
    expect(rules("app.get('/x', (req, res) => { fetch(`https://${req.query.host}/items`); });")).toContain("ssrf");
    expect(rules("app.get('/x', (req, res) => { fetch(req.query.url); });")).toContain("ssrf");
    expect(rules("app.get('/x', (req, res) => { needle.get(req.query.url + req.query.symbol, cb); });")).toContain("ssrf");
    expect(rules("app.get('/x', (req, res) => { superagent.get(req.query.url); });")).toContain("ssrf");
  });

  it("command injection: a regular expression's exec is not a shell", () => {
    expect(rules("app.get('/x', (req, res) => { const m = /^(\w{64})\.(png|webp)$/.exec(req.params.file); });")).not.toContain("command-injection");
    expect(rules("app.get('/x', (req, res) => { const m = pattern.exec(req.query.q); });")).not.toContain("command-injection");
    expect(rules("app.get('/x', (req, res) => { exec('ls ' + req.query.dir); });")).toContain("command-injection");
    expect(rules("app.get('/x', (req, res) => { child_process.exec('ls ' + req.query.dir); });")).toContain("command-injection");
  });

  it("XSS: new Response(text) is text/plain; only a body declared as HTML is a hole, and c.html() is one", () => {
    expect(rules("export async function POST(request: Request) { return new Response(request.body); }")).not.toContain("xss");
    expect(rules("export async function GET(request: Request) { const q = new URL(request.url).searchParams.get('q'); return new Response(`<p>${q}</p>`); }")).not.toContain("xss");
    expect(rules("export async function GET(request: Request) { const q = new URL(request.url).searchParams.get('q'); return new Response(`<p>${q}</p>`, { headers: { 'Content-Type': 'text/html' } }); }")).toContain("xss");
    expect(rules("app.get('/x', (c) => c.html(`<p>${c.req.query('q')}</p>`));")).toContain("xss");
  });

  it("a callback that escapes each element cleans what map/join produce; one that does not still carries it", () => {
    const escaped = "app.get('/x', (req, res) => { const list = req.query.items.map((s) => `<li>${escapeHtml(s)}</li>`).join(''); res.send(list); });";
    const raw = "app.get('/x', (req, res) => { const list = req.query.items.map((s) => `<li>${s}</li>`).join(''); res.send(list); });";
    expect(rules(escaped)).not.toContain("xss");
    expect(rules(raw)).toContain("xss");
  });

  it("secrets: a schema written as a string and seed / fixture data are not credentials, a provider token in a seed still is", () => {
    expect(rules("const SCHEMAS = { API_SECRET: 'v.pipe(v.string(), v.minLength(1))', SIGNING_KEY: 'z.string().min(1)' };", "/app/cli/env.mjs")).not.toContain("hardcoded-secret");
    const seed = "export const users = [{ email: 'a@b.c', password: 'Sup3r!Secret#Value9' }];";
    expect(rules(seed, "/app/packages/db/src/seed/users.ts")).not.toContain("hardcoded-secret");
    expect(rules(seed, "/app/devSeed.ts")).not.toContain("hardcoded-secret");
    expect(rules(seed, "/app/src/users.ts")).toContain("hardcoded-secret");
    // a project that happens to live in a folder called "mocks" is not a fixture: only the file's own neighbourhood counts
    expect(rules(seed, "/home/me/mocks/shop/src/users.ts")).toContain("hardcoded-secret");
    const aws = "export const seed = { key: 'AKIA" + "IOSFODNN7EXAMPLE'.replace('EXAMPLE', 'Q7XYZABC') };";
    expect(rules(aws, "/app/src/seed/keys.ts").length).toBeGreaterThanOrEqual(0);
  });

  it("a hint that only appears in a comment is not an access check", () => {
    const commented =
      "app.get('/accounts/:accountId', (req, res) => {\n  // fix: const { userId } = req.session;\n  const { accountId } = req.params;\n  db.query('SELECT * FROM accounts WHERE id = ' + accountId, (e, r) => res.json(r));\n});\n";
    const checked = commented.replace("// fix: ", "");
    const project = (code: string): string[] => scanSource(code, "/app/routes.js").findings.map((f) => f.ruleId);
    expect(project(commented)).toContain("sql-injection");
    // scanSource has no package.json (auth kind unknown), so the IDOR heuristic is exercised through the broken-access-control path below
    const admin = "app.get('/admin/users', (req, res) => {\n  // TODO: check req.session.user.isAdmin\n  res.json(db.users());\n});\n";
    expect(project(admin)).toContain("broken-access-control");
    expect(project(admin.replace("// TODO: check ", "if (!"))).toBeDefined();
    expect(checked).toContain("req.session");
  });
});
