import { scanSource } from "../src/index";
import { CodeInjectionAnalyzer } from "../src/analyzers/code-injection";
import { OpenRedirectAnalyzer } from "../src/analyzers/open-redirect";
import { NoSqlInjectionAnalyzer } from "../src/analyzers/nosql-injection";
import { InsecureDeserializationAnalyzer } from "../src/analyzers/insecure-deserialization";
import { XxeAnalyzer } from "../src/analyzers/xxe";

const scan = (source: string, analyzer: Parameters<typeof scanSource>[2], file = "app.js") =>
  scanSource(source, file, analyzer).findings;

describe("code-injection", () => {
  const a = [new CodeInjectionAnalyzer()];

  it("flags eval() of request data (NodeGoat contributions.js)", () => {
    const f = scan(`app.post("/c", (req, res) => { const preTax = eval(req.body.preTax); });`, a);
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("code-injection");
    expect(f[0]?.severity).toBe("critical");
  });

  it("flags math.eval / new Function / vm.runInNewContext", () => {
    expect(scan(`app.post("/c", (req, res) => { mathjs.eval(req.body.eqn); });`, a)).toHaveLength(1);
    expect(scan(`app.post("/c", (req, res) => { new Function(req.body.code)(); });`, a)).toHaveLength(1);
    expect(scan(`app.post("/c", (req, res) => { vm.runInNewContext(req.body.code); });`, a)).toHaveLength(1);
  });

  it("follows a variable into eval", () => {
    expect(scan(`app.post("/c", (req, res) => { const e = req.body.expr; eval(e); });`, a)).toHaveLength(1);
  });

  it("does not flag eval of a constant, or JSON.parse of request data", () => {
    expect(scan(`function f() { eval("1 + 1"); }`, a)).toHaveLength(0);
    expect(scan(`app.post("/c", (req, res) => { JSON.parse(req.body.data); });`, a)).toHaveLength(0);
  });
});

describe("open-redirect", () => {
  const a = [new OpenRedirectAnalyzer()];

  it("flags res.redirect(req.query.url) (NodeGoat index.js)", () => {
    const f = scan(`app.get("/learn", (req, res) => res.redirect(req.query.url));`, a);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
  });

  it("flags the (status, url) form, Next.js redirect() and NextResponse.redirect()", () => {
    expect(scan(`app.get("/a", (req, res) => res.redirect(301, req.query.next));`, a)).toHaveLength(1);
    expect(
      scan(`export async function GET(request) { const next = request.nextUrl.searchParams.get("next"); redirect(next); }`, a, "route.ts"),
    ).toHaveLength(1);
    expect(
      scan(`export async function GET(request) { const n = request.nextUrl.searchParams.get("n"); return NextResponse.redirect(n); }`, a, "route.ts"),
    ).toHaveLength(1);
  });

  it("does not flag a redirect to a fixed same-site path with data appended", () => {
    expect(scan(`app.get("/a", (req, res) => res.redirect("/items/" + req.params.id));`, a)).toHaveLength(0);
    expect(scan("app.get('/a', (req, res) => res.redirect(`/items/${req.query.id}`));", a)).toHaveLength(0);
  });

  it("still flags // (protocol-relative) and bare user targets", () => {
    expect(scan(`app.get("/a", (req, res) => res.redirect("//" + req.query.host));`, a)).toHaveLength(1);
  });

  it("does not flag redirects to constants", () => {
    expect(scan(`app.get("/a", (req, res) => res.redirect("/login"));`, a)).toHaveLength(0);
  });
});

describe("insecure-deserialization", () => {
  const a = [new InsecureDeserializationAnalyzer()];

  it("flags node-serialize unserialize of uploaded data (dvna appHandler.js)", () => {
    const f = scan(
      `app.post("/b", (req, res) => { const products = serialize.unserialize(req.files.products.data.toString("utf8")); });`,
      a,
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("critical");
  });

  it("does not flag JSON.parse", () => {
    expect(scan(`app.post("/b", (req, res) => { JSON.parse(req.body.data); });`, a)).toHaveLength(0);
  });
});

describe("xxe", () => {
  const a = [new XxeAnalyzer()];

  it("flags libxmljs parsing request XML with noent:true (dvna appHandler.js)", () => {
    const f = scan(
      `app.post("/b", (req, res) => { libxmljs.parseXmlString(req.files.products.data.toString("utf8"), {noent:true,noblanks:true}); });`,
      a,
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("xxe");
  });

  it("does not flag the same parse without noent (entities stay off)", () => {
    expect(scan(`app.post("/b", (req, res) => { libxmljs.parseXmlString(req.body.xml); });`, a)).toHaveLength(0);
    expect(scan(`app.post("/b", (req, res) => { libxmljs.parseXmlString(req.body.xml, {noblanks:true}); });`, a)).toHaveLength(0);
  });
});

describe("nosql-injection", () => {
  const a = [new NoSqlInjectionAnalyzer()];

  describe("operator injection", () => {
    it("flags request body used directly as a Mongo query value", () => {
      const f = scan(`app.post("/login", (req, res) => { User.findOne({ username: req.body.username, password: req.body.password }); });`, a);
      expect(f.length).toBeGreaterThan(0);
      expect(f[0]?.ruleId).toBe("nosql-injection");
    });

    it("flags an aliased body value and a Next.js request.json() body", () => {
      expect(scan(`app.get("/u", (req, res) => { const n = req.query.name; User.find({ name: n }); });`, a)).toHaveLength(1);
      expect(
        scan(`export async function POST(request) { const body = await request.json(); await users.findOne({ email: body.email }); }`, a, "route.ts"),
      ).toHaveLength(1);
    });

    it("does not flag values forced to a string, or pinned with $eq (hackathon-starter pattern)", () => {
      expect(scan(`app.post("/l", (req, res) => { User.findOne({ username: String(req.body.username) }); });`, a)).toHaveLength(0);
      expect(scan(`app.post("/l", (req, res) => { User.findOne({ email: { $eq: req.body.email } }); });`, a)).toHaveLength(0);
      expect(scan(`app.post("/l", (req, res) => { User.findOne({ email: req.body.email.toLowerCase() }); });`, a)).toHaveLength(0);
    });

    it("does not flag req.params or searchParams (always strings)", () => {
      expect(scan(`app.get("/u/:id", (req, res) => { User.findOne({ _id: req.params.id }); });`, a)).toHaveLength(0);
      expect(
        scan(`export async function GET(request) { const s = request.nextUrl.searchParams.get("s"); await users.find({ slug: s }); }`, a, "route.ts"),
      ).toHaveLength(0);
    });
  });

  describe("$where", () => {
    it("flags a $where built from an interpolated value (NodeGoat allocations-dao.js)", () => {
      const source = "function get(userId, threshold) { return { $where: `this.userId == ${userId} && this.stocks > '${threshold}'` }; }";
      const f = scan(source, a);
      expect(f).toHaveLength(1);
      expect(f[0]?.severity).toBe("high");
    });

    it("flags string concatenation into $where", () => {
      expect(scan(`function q(t) { return { $where: "this.x > " + t }; }`, a)).toHaveLength(1);
    });

    it("does not flag a static $where", () => {
      expect(scan(`function q() { return { $where: "this.x > 5" }; }`, a)).toHaveLength(0);
    });

    it("does not flag a $where whose parts were coerced to numbers (the fixed NodeGoat version)", () => {
      const source =
        "function q(userId, threshold) { const parsedUserId = parseInt(userId, 10); const parsedThreshold = parseInt(threshold, 10); " +
        "return { $where: `this.userId == ${parsedUserId} && this.stocks > ${parsedThreshold}` }; }";
      expect(scan(source, a)).toHaveLength(0);
    });
  });
});
