import * as fs from "fs";
import * as path from "path";
import { RULE_IDS } from "./suppress";
import { Severity, VulnerabilityType } from "./types";

/**
 * A project's own settings, in `.security-hub.json` at the root of the scanned folder, so a team states them once
 * instead of repeating flags in every script and workflow:
 *
 *   {
 *     "ignore": ["legacy/", "scripts/**"],       // path patterns to skip (same syntax as .security-hub-ignore)
 *     "disable": ["csrf", "missing-rate-limit"],  // rules this project does not want reported
 *     "severity": "medium",                       // report only findings at or above this
 *     "failOn": "high",                           // exit 1 when a reported finding is at or above this
 *     "includeTests": false
 *   }
 *
 * Command-line flags and Action inputs win over the file. A typo in the file is an error, never silently ignored:
 * a setting that does nothing is how a project believes a rule is off (or on) when it is not.
 */
export const CONFIG_FILE_NAME = ".security-hub.json";

export interface HubConfig {
  ignore: string[];
  disable: VulnerabilityType[];
  severity?: Severity;
  failOn?: Severity;
  includeTests?: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const SETTINGS = ["ignore", "disable", "severity", "failOn", "includeTests"] as const;
const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];
const MAX_CONFIG_BYTES = 256 * 1024;

// a Windows editor may put a byte-order mark in front of the JSON
function stripByteOrderMark(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function emptyConfig(): HubConfig {
  return { ignore: [], disable: [] };
}

function severityOf(value: unknown, name: string, source: string): Severity {
  if (typeof value !== "string" || !SEVERITIES.includes(value as Severity)) {
    throw new ConfigError(`${source}: "${name}" must be one of ${SEVERITIES.join(", ")} (got ${JSON.stringify(value)}).`);
  }
  return value as Severity;
}

/** Parses and checks the text of a config file; throws a ConfigError that names the file and the setting. */
export function parseConfig(text: string, source: string = CONFIG_FILE_NAME): HubConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(stripByteOrderMark(text));
  } catch (err) {
    throw new ConfigError(`${source}: not valid JSON (${(err as Error).message}). Comments and trailing commas are not allowed.`);
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${source}: the file must hold one JSON object, like {"disable": ["csrf"]}.`);
  }
  const settings = raw as Record<string, unknown>;
  for (const key of Object.keys(settings)) {
    if (key !== "$schema" && !(SETTINGS as readonly string[]).includes(key)) {
      throw new ConfigError(`${source}: unknown setting "${key}". Known settings: ${SETTINGS.join(", ")}.`);
    }
  }

  const config = emptyConfig();
  if (settings.ignore !== undefined) {
    if (!Array.isArray(settings.ignore) || settings.ignore.some((p) => typeof p !== "string" || p.trim() === "")) {
      throw new ConfigError(`${source}: "ignore" must be a list of path patterns, like ["legacy/", "scripts/**"].`);
    }
    config.ignore = (settings.ignore as string[]).map((p) => p.trim());
  }
  if (settings.disable !== undefined) {
    if (!Array.isArray(settings.disable)) throw new ConfigError(`${source}: "disable" must be a list of rule ids, like ["csrf"].`);
    for (const id of settings.disable) {
      if (typeof id !== "string" || !(RULE_IDS as readonly string[]).includes(id)) {
        throw new ConfigError(`${source}: "disable" names an unknown rule ${JSON.stringify(id)}. Rules: ${RULE_IDS.join(", ")}.`);
      }
    }
    config.disable = [...new Set(settings.disable as VulnerabilityType[])];
  }
  if (settings.severity !== undefined) config.severity = severityOf(settings.severity, "severity", source);
  if (settings.failOn !== undefined) config.failOn = severityOf(settings.failOn, "failOn", source);
  if (settings.includeTests !== undefined) {
    if (typeof settings.includeTests !== "boolean") throw new ConfigError(`${source}: "includeTests" must be true or false.`);
    config.includeTests = settings.includeTests;
  }
  return config;
}

/**
 * The settings for the scan of `directory`: `.security-hub.json` in it, or the file named by `explicitFile`.
 * No file is not an error (the defaults apply); a named file that is missing, too large or wrong is.
 */
export function loadConfig(directory: string, explicitFile?: string): { config: HubConfig; file?: string } {
  const file = explicitFile ? path.resolve(explicitFile) : path.join(directory, CONFIG_FILE_NAME);
  let size: number;
  try {
    size = fs.statSync(file).size;
  } catch {
    if (explicitFile) throw new ConfigError(`Config file not found: ${explicitFile}`);
    return { config: emptyConfig() };
  }
  if (size > MAX_CONFIG_BYTES) throw new ConfigError(`${path.basename(file)}: too large for a settings file (${size} bytes).`);
  return { config: parseConfig(fs.readFileSync(file, "utf8"), path.basename(file)), file };
}
