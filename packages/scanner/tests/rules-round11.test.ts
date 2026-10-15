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
