#!/usr/bin/env node
// E2E check for the SQL injection lab: proves the vulnerability is real in
// the default (vulnerable) mode, AND that the parameterized-query fix
// (SAFE_MODE=1) actually closes it. Run with `npm run lab:sql-injection:e2e`.
const { execFileSync } = require("child_process");
const path = require("path");

const COMPOSE_FILE = path.join(__dirname, "docker-compose.yml");
const BASE_URL = "http://localhost:3300";
const SECRET = "FLAG{sql_injection_via_category_param}";
const EXPLOIT_PAYLOAD = "nonexistent' UNION SELECT id, username, secret_token FROM users-- ";

function compose(args, env = {}) {
  execFileSync("docker", ["compose", "-f", COMPOSE_FILE, ...args], {
    stdio: "inherit",
    env: { ...process.env, ...env },
  });
}

async function waitForHealth(timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Lab container did not become healthy in time");
}

async function attemptExploit() {
  const url = `${BASE_URL}/products?category=${encodeURIComponent(EXPLOIT_PAYLOAD)}`;
  const res = await fetch(url);
  const body = await res.text();
  return body.includes(SECRET);
}

async function runPhase(label, safeMode, expectExploitable) {
  console.log(`\n=== ${label} (SAFE_MODE=${safeMode}) ===`);
  try {
    compose(["up", "-d", "--build"], { SAFE_MODE: safeMode });
    await waitForHealth();
    const exploited = await attemptExploit();
    console.log(
      exploited
        ? "  -> Exploit succeeded: leaked users.secret_token via the category param."
        : "  -> Exploit did not leak the secret token.",
    );
    if (exploited !== expectExploitable) {
      throw new Error(`Expected exploitable=${expectExploitable} but observed exploitable=${exploited}`);
    }
  } finally {
    try {
      compose(["down", "-v"]);
    } catch (cleanupErr) {
      console.error("Warning: cleanup (docker compose down) failed:", cleanupErr.message);
    }
  }
}

async function main() {
  await runPhase("Vulnerable mode", "0", true);
  await runPhase("Safe mode (parameterized query fix)", "1", false);
  console.log("\nAll checks passed: the vulnerability is exploitable, and the fix actually closes it.");
}

main().catch((err) => {
  console.error("\nE2E FAILED:", err.message);
  process.exit(1);
});
