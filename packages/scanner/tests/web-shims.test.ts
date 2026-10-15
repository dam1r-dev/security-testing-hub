import * as nodePath from "path";
import * as webPath from "../web/shims/path";
import * as virtualFs from "../web/shims/fs";

// The scanner on the web page runs on these stand-ins for `path` and `fs`; they must answer like the real ones.
const posix = nodePath.posix;

describe("web shim: path", () => {
  const paths = ["", ".", "..", "/", "//", "/a", "/a/", "/a/b", "/a/b/", "a", "a/b", "a/b/", "./a", "../a", "a/../b", "a/./b", "/a/../..", "/a//b", "a//b//c/", "../../x/y", "/a/b/../c/./d", ".hidden", "/a/.hidden", "/a/b.c.d", "/a/b.", "/a/..", "file.ts", "/x/y/file.test.ts", "/a/b/c.js/", "C:/a/b"];

  it.each(paths)("normalize, dirname, basename, extname, isAbsolute of %j", (p) => {
    expect(webPath.normalize(p)).toBe(posix.normalize(p));
    expect(webPath.dirname(p)).toBe(posix.dirname(p));
    expect(webPath.basename(p)).toBe(posix.basename(p));
    expect(webPath.basename(p, ".js")).toBe(posix.basename(p, ".js"));
    expect(webPath.extname(p)).toBe(posix.extname(p));
    expect(webPath.isAbsolute(p)).toBe(posix.isAbsolute(p));
  });

  it("join and relative agree with node on every pair", () => {
    for (const a of paths) {
      for (const b of paths) {
        expect(webPath.join(a, b)).toBe(posix.join(a, b));
        if (a.startsWith("/") && b.startsWith("/")) expect(webPath.relative(a, b)).toBe(posix.relative(a, b));
      }
    }
  });

  it("resolve treats the page's root as the working directory", () => {
    expect(webPath.resolve("/project", "src", "../lib/a.ts")).toBe("/project/lib/a.ts");
    expect(webPath.resolve("/project/src", "/other", "x")).toBe("/other/x");
    expect(webPath.resolve("a", "b")).toBe("/a/b");
    expect(webPath.resolve("/a/b/")).toBe("/a/b");
    expect(webPath.resolve("/")).toBe("/");
    expect(webPath.sep).toBe("/");
  });
});

describe("web shim: fs", () => {
  beforeEach(() => {
    virtualFs.mount("/project", [
      { path: "app.js", size: 11, text: "const a = 1" },
      { path: "src/lib/util.ts", size: 3, text: "ü" },
      { path: "public/logo.png", size: 5000 }, // listed, content not read
      { path: ".env", size: 4, text: "A=1\n" },
    ]);
  });
  afterEach(() => virtualFs.unmount());

  it("reads text, sizes and kinds", () => {
    expect(virtualFs.readFileSync("/project/app.js", "utf8")).toBe("const a = 1");
    expect(virtualFs.statSync("/project/public/logo.png").size).toBe(5000);
    expect(virtualFs.statSync("/project/src").isDirectory()).toBe(true);
    expect(virtualFs.statSync("/project/app.js").isFile()).toBe(true);
    expect(virtualFs.existsSync("/project/src/lib")).toBe(true);
    expect(virtualFs.existsSync("/project/nope.js")).toBe(false);
  });

  it("lists directories like readdirSync with file types, sorted", () => {
    const entries = virtualFs.readdirSync("/project", { withFileTypes: true }) as virtualFs.Dirent[];
    expect(entries.map((e) => `${e.name}:${e.isDirectory() ? "d" : "f"}`)).toEqual([".env:f", "app.js:f", "public:d", "src:d"]);
    expect(entries.every((e) => !e.isSymbolicLink())).toBe(true);
    expect(virtualFs.readdirSync("/project/src")).toEqual(["lib"]);
  });

  it("reads the head of a file through a descriptor", () => {
    const fd = virtualFs.openSync("/project/src/lib/util.ts");
    const buffer = new Uint8Array(16);
    const read = virtualFs.readSync(fd, buffer, 0, 16, 0);
    virtualFs.closeSync(fd);
    expect(new TextDecoder().decode(buffer.subarray(0, read))).toBe("ü");
    expect(read).toBe(2); // two UTF-8 bytes
  });

  it("fails the way node does: an error with code ENOENT", () => {
    expect(() => virtualFs.readFileSync("/project/missing.js", "utf8")).toThrow(/ENOENT/);
    expect(() => virtualFs.statSync("/elsewhere")).toThrow(/ENOENT/);
    expect(() => virtualFs.readdirSync("/project/app.js")).toThrow(/ENOENT/);
  });

  it("forgets everything when unmounted", () => {
    virtualFs.unmount();
    expect(virtualFs.existsSync("/project/app.js")).toBe(false);
  });
});
