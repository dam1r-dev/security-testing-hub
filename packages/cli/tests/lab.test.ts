import { spawnSync } from "child_process";
import { runLab } from "../src/commands/lab";

jest.mock("child_process", () => ({ spawnSync: jest.fn() }));

const mockSpawnSync = spawnSync as jest.MockedFunction<typeof spawnSync>;

describe("runLab", () => {
  let logSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;

  beforeEach(() => {
    mockSpawnSync.mockReset();
    logSpy = jest.spyOn(console, "log").mockImplementation(() => undefined);
    errorSpy = jest.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it("lists available labs and exits 0 when no name is given", () => {
    const exitCode = runLab(undefined, {});
    expect(exitCode).toBe(0);
    expect(mockSpawnSync).not.toHaveBeenCalled();
    expect(logSpy.mock.calls.flat().join("\n")).toContain("sql-injection");
  });

  it("rejects an unknown lab name without touching Docker", () => {
    const exitCode = runLab("nonexistent-lab", {});
    expect(exitCode).toBe(2);
    expect(mockSpawnSync).not.toHaveBeenCalled();
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("Unknown lab");
  });

  it("reports a clear error when Docker itself isn't available", () => {
    mockSpawnSync.mockReturnValue({
      error: new Error("spawn docker ENOENT"),
      status: null,
      signal: null,
      output: [],
      pid: 0,
      stdout: "",
      stderr: "",
    } as unknown as ReturnType<typeof spawnSync>);

    const exitCode = runLab("sql-injection", {});
    expect(exitCode).toBe(1);
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("Could not run Docker");
  });

  it("propagates a non-zero docker compose exit code", () => {
    mockSpawnSync.mockReturnValue({
      error: undefined,
      status: 1,
      signal: null,
      output: [],
      pid: 0,
      stdout: "",
      stderr: "",
    } as unknown as ReturnType<typeof spawnSync>);

    const exitCode = runLab("sql-injection", {});
    expect(exitCode).toBe(1);
  });

  it("calls docker compose with 'up -d --build' by default, and 'down -v' with --stop", () => {
    mockSpawnSync.mockReturnValue({
      error: undefined,
      status: 0,
      signal: null,
      output: [],
      pid: 0,
      stdout: "",
      stderr: "",
    } as unknown as ReturnType<typeof spawnSync>);

    runLab("sql-injection", {});
    expect(mockSpawnSync.mock.calls[0]?.[1]).toEqual(
      expect.arrayContaining(["compose", "-f", expect.stringContaining("docker-compose.yml"), "up", "-d", "--build"]),
    );

    mockSpawnSync.mockClear();
    const exitCode = runLab("sql-injection", { stop: true });
    expect(mockSpawnSync.mock.calls[0]?.[1]).toEqual(
      expect.arrayContaining(["compose", "-f", expect.stringContaining("docker-compose.yml"), "down", "-v"]),
    );
    expect(exitCode).toBe(0);
  });
});
