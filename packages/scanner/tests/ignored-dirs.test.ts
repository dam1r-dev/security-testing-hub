import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src/index";

describe("scanPath ignored directories", () => {
  let projectDir: string;

  beforeEach(() => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-hub-ignore-test-"));
    // Same shape Prisma emits: valid modern TS our grammar can't parse yet.
    fs.mkdirSync(path.join(projectDir, "src", "generated", "prisma"), { recursive: true });
    fs.writeFileSync(
      path.join(projectDir, "src", "generated", "prisma", "models.ts"),
      `export type * from './models/User'\n`,
    );
    fs.mkdirSync(path.join(projectDir, "src", "__generated__"), { recursive: true });
    fs.writeFileSync(path.join(projectDir, "src", "__generated__", "types.ts"), `export type * from './x'\n`);
    fs.writeFileSync(path.join(projectDir, "src", "app.ts"), `export const answer = 42;\n`);
  });

  afterEach(() => {
    fs.rmSync(projectDir, { recursive: true, force: true });
  });

  it("skips generated/ and __generated__/ so they don't produce parse warnings", () => {
    const summary = scanPath(projectDir);
    expect(summary.filesScanned).toBe(1);
    expect(summary.results.every((r) => !r.parseError)).toBe(true);
    expect(summary.results[0]?.file.endsWith("app.ts")).toBe(true);
  });
});
