jest.mock("../src/commands/scan", () => ({ runScan: jest.fn() }));
jest.mock("../src/commands/lab", () => ({ runLab: jest.fn() }));
jest.mock("../src/commands/ui", () => ({ runUi: jest.fn() }));

import { run } from "../src/index";
import { runScan } from "../src/commands/scan";
import { runLab } from "../src/commands/lab";
import { runUi } from "../src/commands/ui";

const mockRunScan = runScan as jest.MockedFunction<typeof runScan>;
const mockRunLab = runLab as jest.MockedFunction<typeof runLab>;
const mockRunUi = runUi as jest.MockedFunction<typeof runUi>;

describe("CLI argument parsing (run)", () => {
  let logSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;

  beforeEach(() => {
    mockRunScan.mockReset();
    mockRunLab.mockReset();
    mockRunUi.mockReset();
    process.exitCode = undefined;
    logSpy = jest.spyOn(console, "log").mockImplementation(() => undefined);
    errorSpy = jest.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    process.exitCode = undefined;
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it("dispatches 'scan <path>' with default options", () => {
    mockRunScan.mockReturnValue(0);
    run(["node", "security-hub", "scan", "./some-app"]);
    expect(mockRunScan).toHaveBeenCalledWith("./some-app", {
      format: "text",
      out: undefined,
      severity: undefined,
      failOn: undefined,
    });
    expect(process.exitCode).toBe(0);
  });

  it("passes through --format/--out/--severity/--fail-on", () => {
    mockRunScan.mockReturnValue(1);
    run([
      "node",
      "security-hub",
      "scan",
      "./some-app",
      "--format",
      "json",
      "--out",
      "out.json",
      "--severity",
      "high",
      "--fail-on",
      "critical",
    ]);
    expect(mockRunScan).toHaveBeenCalledWith("./some-app", {
      format: "json",
      out: "out.json",
      severity: "high",
      failOn: "critical",
    });
    expect(process.exitCode).toBe(1);
  });

  it("rejects an invalid --format before ever calling runScan", () => {
    run(["node", "security-hub", "scan", "./some-app", "--format", "yaml"]);
    expect(mockRunScan).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("Invalid format");
  });

  it("throws on an invalid --severity value", () => {
    expect(() => run(["node", "security-hub", "scan", "./some-app", "--severity", "extreme"])).toThrow(
      /Invalid severity/,
    );
  });

  it("dispatches 'lab <name>' with --stop", () => {
    mockRunLab.mockReturnValue(0);
    run(["node", "security-hub", "lab", "sql-injection", "--stop"]);
    expect(mockRunLab).toHaveBeenCalledWith("sql-injection", { stop: true });
    expect(process.exitCode).toBe(0);
  });

  it("dispatches 'lab' with no name and no --stop", () => {
    mockRunLab.mockReturnValue(0);
    run(["node", "security-hub", "lab"]);
    expect(mockRunLab).toHaveBeenCalledWith(undefined, { stop: false });
  });

  it("prints a placeholder message for 'docs'", () => {
    run(["node", "security-hub", "docs"]);
    expect(logSpy.mock.calls.flat().join(" ")).toContain("docs/rules.md");
  });

  it("passes repeatable --ignore patterns and --include-tests to the scan", () => {
    mockRunScan.mockReturnValue(0);
    run(["node", "security-hub", "scan", "./app", "--ignore", "legacy/", "--ignore", "*.mock.js", "--include-tests"]);
    expect(mockRunScan).toHaveBeenCalledWith(
      "./app",
      expect.objectContaining({ ignore: ["legacy/", "*.mock.js"], includeTests: true }),
    );
  });

  it("passes --changed-since and the new formats through", () => {
    mockRunScan.mockReturnValue(0);
    run(["node", "security-hub", "scan", ".", "--format", "markdown", "--changed-since", "origin/main"]);
    expect(mockRunScan).toHaveBeenCalledWith(".", expect.objectContaining({ format: "markdown", changedSince: "origin/main" }));
    run(["node", "security-hub", "scan", ".", "--format", "github"]);
    expect(mockRunScan).toHaveBeenLastCalledWith(".", expect.objectContaining({ format: "github" }));
  });

  it("dispatches 'ui' with defaults, a path, a port and --no-open", async () => {
    mockRunUi.mockResolvedValue(0);
    run(["node", "security-hub", "ui"]);
    expect(mockRunUi).toHaveBeenLastCalledWith({ path: undefined, port: undefined, open: true });

    run(["node", "security-hub", "ui", "./app", "--port", "5000", "--no-open"]);
    expect(mockRunUi).toHaveBeenLastCalledWith({ path: "./app", port: 5000, open: false });
  });

  it("rejects an invalid --port for 'ui'", () => {
    run(["node", "security-hub", "ui", "--port", "99999"]);
    expect(mockRunUi).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
  });
});
