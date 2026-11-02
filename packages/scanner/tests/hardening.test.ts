import { scanSource } from "../src";

const js = (code: string, rule?: string, file = "/app/server.js"): string[] => scanSource(code, file).findings.filter((f) => !rule || f.ruleId === rule).map((f) => f.ruleId);

describe("weak-crypto (JavaScript)", () => {
  it("a password hashed with MD5 or SHA-1 is reported, a checksum is not", () => {
    expect(js('const crypto = require("crypto"); const hashPassword = (password) => crypto.createHash("md5").update(password).digest("hex");', "weak-crypto")).toHaveLength(1);
    expect(js('function f(pw) { return crypto.createHash("sha1").update(pw).digest("hex"); }\nfunction hashPassword(x) { return crypto.createHash("sha1").update(x).digest("hex"); }', "weak-crypto")).toHaveLength(1);
    expect(js('const etag = crypto.createHash("md5").update(fileContents).digest("hex");', "weak-crypto")).toHaveLength(0);
    expect(js('const h = crypto.createHash("sha256").update(password).digest("hex");', "weak-crypto")).toHaveLength(0); // fast, but not the broken ones
  });

  it("Math.random() for a token, a code or a session id; not for a colour or a delay", () => {
    expect(js("const resetToken = Math.random().toString(36).slice(2);", "weak-crypto")).toHaveLength(1);
    expect(js("function makeSessionId() { return Math.random().toString(16); }", "weak-crypto")).toHaveLength(1);
    expect(js("const user = { otp: Math.floor(Math.random() * 1e6) };", "weak-crypto")).toHaveLength(1);
    expect(js("const color = Math.random() > 0.5 ? 'red' : 'blue'; const retryDelay = 100 * Math.random(); const pick = items[Math.floor(Math.random() * items.length)];", "weak-crypto")).toHaveLength(0);
    expect(js("const sessionColor = Math.random();", "weak-crypto")).toHaveLength(0);
  });

  it("bcrypt with a cost below 10; 12 is fine", () => {
    expect(js("await bcrypt.hash(req.body.password, 4);", "weak-crypto")).toHaveLength(1);
    expect(js("const salt = bcrypt.genSaltSync(8);", "weak-crypto")).toHaveLength(1);
    expect(js("await bcrypt.hash(password, 12); await bcryptjs.hash(password, 10);", "weak-crypto")).toHaveLength(0);
    expect(js("await bcrypt.hash(password, saltRounds);", "weak-crypto")).toHaveLength(0);
  });

  it("ECB, DES, RC4 and createCipher; AES-GCM is fine", () => {
    expect(js('crypto.createCipheriv("aes-128-ecb", key, null);', "weak-crypto")).toHaveLength(1);
    expect(js('crypto.createCipheriv("des-cbc", key, iv);', "weak-crypto")).toHaveLength(1);
    expect(js('crypto.createCipher("aes192", password);', "weak-crypto")).toHaveLength(1);
    expect(js('crypto.createCipheriv("aes-256-gcm", key, iv); crypto.createCipheriv("des-ede3-cbc", key, iv);', "weak-crypto")).toHaveLength(0);
  });
});

describe("insecure-cookie (JavaScript)", () => {
  it("express-session / cookie-session with httpOnly: false or secure: false", () => {
    expect(js('app.use(session({ secret: s, cookie: { httpOnly: false } }));', "insecure-cookie")).toHaveLength(1);
    expect(js('app.use(session({ secret: s, cookie: { secure: false, httpOnly: false } }));', "insecure-cookie")).toHaveLength(2);
    expect(js('app.use(cookieSession({ name: "s", keys: [k], httpOnly: false }));', "insecure-cookie")).toHaveLength(1);
    expect(js('app.use(session({ secret: s, cookie: { secure: true, httpOnly: true } }));', "insecure-cookie")).toHaveLength(0);
    expect(js('app.use(session({ secret: s }));', "insecure-cookie")).toHaveLength(0); // defaults: httpOnly on
  });

  it("res.cookie for a login cookie without httpOnly: true", () => {
    expect(js('res.cookie("token", jwt);', "insecure-cookie")).toHaveLength(1);
    expect(js('res.cookie("session", id, { maxAge: 1000 });', "insecure-cookie")).toHaveLength(1);
    expect(js('res.cookie("refreshToken", t, { httpOnly: false });', "insecure-cookie")).toHaveLength(1);
    expect(js('res.cookie("token", jwt, { httpOnly: true, secure: false });', "insecure-cookie")).toHaveLength(1);
    expect(js('res.cookie("token", jwt, { httpOnly: true, secure: true, sameSite: "lax" });', "insecure-cookie")).toHaveLength(0);
    expect(js('res.cookie("theme", "dark"); res.cookie("lang", "en", {});', "insecure-cookie")).toHaveLength(0); // meant for scripts
    expect(js('res.cookie("token", jwt, options);', "insecure-cookie")).toHaveLength(0); // options in a variable: not seen
  });

  it("secure: false outside a cookie (mail server, dev proxy) is not a cookie problem", () => {
    expect(js('const transport = nodemailer.createTransport({ host: h, port: 587, secure: false });', "insecure-cookie")).toHaveLength(0);
  });
});

describe("tls-verification (JavaScript)", () => {
  it("rejectUnauthorized: false, strictSSL: false, NODE_TLS_REJECT_UNAUTHORIZED = 0", () => {
    expect(js("const agent = new https.Agent({ rejectUnauthorized: false });", "tls-verification")).toHaveLength(1);
    expect(js("request({ url, strictSSL: false });", "tls-verification")).toHaveLength(1);
    expect(js('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";', "tls-verification")).toHaveLength(1);
    expect(js("process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;", "tls-verification")).toHaveLength(1);
    expect(js('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1"; const a = { rejectUnauthorized: true, other: process.env.NODE_ENV === "production" };', "tls-verification")).toHaveLength(0);
  });

  it("a certificate inspector (connect, read the certificate, send nothing) is left alone", () => {
    const inspector = 'function check(host) { const s = tls.connect({ host, port: 443, rejectUnauthorized: false }, () => { const cert = s.getPeerCertificate(); done(cert.valid_to); }); }';
    expect(js(inspector, "tls-verification")).toHaveLength(0);
    const sender = 'function call(host) { const s = tls.connect({ host, port: 443, rejectUnauthorized: false }, () => { s.getPeerCertificate(); s.write("POST /login ..."); }); }';
    expect(js(sender, "tls-verification")).toHaveLength(1);
  });
});

describe("regex-injection (JavaScript)", () => {
  it("a pattern built from the request", () => {
    expect(js("app.get('/s', (req, res) => { const re = new RegExp(req.query.q); res.json(re.test('x')); });", "regex-injection")).toHaveLength(1);
    expect(js("app.get('/s', (req, res) => { res.json(RegExp(req.body.pattern, 'i').test('x')); });", "regex-injection")).toHaveLength(1);
  });

  it("escaped or fixed patterns are fine", () => {
    expect(js("app.get('/s', (req, res) => { const re = new RegExp(escapeRegExp(req.query.q), 'i'); res.json(re.test('x')); });", "regex-injection")).toHaveLength(0);
    expect(js("app.get('/s', (req, res) => { const re = new RegExp('^[a-z]+$'); res.json(re.test(req.query.q)); });", "regex-injection")).toHaveLength(0);
  });
});
