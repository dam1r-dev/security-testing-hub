jest.mock("../src/commands/scan", () => ({ runScan: jest.fn() }));
jest.mock("../src/commands/lab", () => ({ runLab: jest.fn() }));

import { run } from "../src/index";
import { runScan } from "../src/commands/scan";
import { runLab } from "../src/commands/lab";

const mockRunScan = runScan as jest.MockedFunction<typeof runScan>;
const mockRunLab = runLab as jest.MockedFunction<typeof runLab>;

describe("CLI argument parsing (run)", () => {
  let logSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;

  beforeEach(() => {
    mockRunScan.mockReset();
    mockRunLab.mockReset();
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
});
