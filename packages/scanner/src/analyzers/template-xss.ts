import * as path from "path";
import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { Finding } from "../types";
import { findViewTemplate, UnsafeUse, viewUnsafeUse } from "../templates";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

/**
 * Stored/reflected XSS through a view engine. `res.render("profile", { bio: req.body.bio })` is safe while the template says `<%= bio %>`
 * (EJS, Pug `#{bio}`, Handlebars `{{bio}}` all escape), and a hole when it says `<%- bio %>`, `!{bio}` or `{{{bio}}}`. The view is found in the
 * project's `views` / `templates` folder, with the partials it includes; only the keys it prints raw are checked, so a value the template
 * escapes is never reported. The `res.send(...)` sinks are in xss.ts.
 */

const RENDER_OBJECT = /^(?:res|response|reply|ctx|context|c)$/;
const RENDER_METHOD = /^(?:render|view)$/;
const DETAIL = "{{DETAIL}}";

export interface RenderCall {
  view: string;
  data: SyntaxNode;
}

export function renderCall(node: SyntaxNode): RenderCall | undefined {
  if (node.type !== "call_expression") return undefined;
  const callee = node.childForFieldName("function");
  if (callee?.type !== "member_expression") return undefined;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property || !RENDER_OBJECT.test(object.text) || !RENDER_METHOD.test(property.text)) return undefined;
  const args = node.childForFieldName("arguments")?.namedChildren ?? [];
  const view = args[0];
  const data = args[1];
  if (view?.type !== "string" || data?.type !== "object") return undefined;
  return { view: view.text.slice(1, -1), data };
}

/** The values of the data object by the name the template sees: `{ bio: x }`, `{ bio }`, `{ "bio": x }`. Spreads are not followed. */
export function dataEntries(data: SyntaxNode): Array<{ key: string; value: SyntaxNode }> {
  const out: Array<{ key: string; value: SyntaxNode }> = [];
  for (const child of data.namedChildren) {
    if (child.type === "pair") {
      const key = child.childForFieldName("key");
      const value = child.childForFieldName("value");
      if (key && value) out.push({ key: key.type === "string" ? key.text.slice(1, -1) : key.text, value });
    } else if (child.type === "shorthand_property_identifier") {
      out.push({ key: child.text, value: child });
    }
  }
  return out;
}

export class TemplateXssAnalyzer extends BaseAnalyzer {
  private root = "";
  /** The unescaped print found for each render call of the file being analysed, by the call's position. */
  private uses = new Map<number, UnsafeUse[]>();
  private displayPath: (file: string) => string = (file) => file;

  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    this.root = context?.root ?? path.dirname(filePath);
    this.uses = new Map();
    this.displayPath = (file) => (context ? context.displayPath(file) : path.relative(this.root, file));
    const findings = this.escapingSwitchedOff(parsed, filePath);
    if (!/\.render\s*\(|\.view\s*\(/.test(parsed.sourceCode)) return findings; // most files render nothing: no taint run
    findings.push(...super.analyze(parsed, filePath, context));
    for (const finding of findings) {
      // the message names the template and the line that prints the value raw (cross-file hits keep the generic text)
      const uses = this.uses.get(this.positionOf(finding, parsed));
      finding.message = finding.message.replace(DETAIL, uses?.[0] ? ` ${this.detail(uses)}` : "");
    }
    return findings;
  }

  /** `swig.setDefaults({ autoescape: false })`, `nunjucks.configure(..., { autoescape: false })`, `handlebars.compile(x, { noEscape: true })`. */
  private escapingSwitchedOff(parsed: ParsedFile, filePath: string): Finding[] {
    if (!/autoescape|noEscape/.test(parsed.sourceCode)) return [];
    const out: Finding[] = [];
    const calls = findNodes(parsed.tree.rootNode, (n) => n.type === "call_expression" || n.type === "new_expression");
    for (const call of calls) {
      const callee = (call.type === "new_expression" ? call.childForFieldName("constructor") : call.childForFieldName("function"))?.text ?? "";
      if (!/(?:^|\.)(?:setDefaults|configure|Environment|compile)$/.test(callee)) continue;
      const off = findNodes(call, (n) => {
        if (n.type !== "pair") return false;
        const key = (n.childForFieldName("key")?.text ?? "").replace(/["']/g, "");
        const value = n.childForFieldName("value")?.text;
        return (key === "autoescape" && value === "false") || (key === "noEscape" && value === "true");
      });
      const setting = off[0];
      if (!setting) continue;
      out.push({
        ruleId: "xss",
        severity: "high",
        confidence: "medium",
        message:
          `The template engine is set to print every value without escaping (${setting.text}). Any text a visitor can influence (a name, a comment, a profile field, anything stored in the database) ` +
          `then runs as script in the page. Turn escaping back on (it is the default) and mark only markup you wrote as safe.`,
        location: toLocation(setting, filePath),
        sourceSnippet: setting.text,
        sinkSnippet: snippet(call, parsed.sourceCode),
      });
    }
    return out;
  }

  private positionOf(finding: Finding, parsed: ParsedFile): number {
    const lines = parsed.sourceCode.split("\n");
    let index = 0;
    for (let i = 0; i < finding.location.startLine - 1; i++) index += (lines[i]?.length ?? 0) + 1;
    return index + finding.location.startColumn - 1;
  }

  private detail(uses: UnsafeUse[]): string {
    // every value the request fills in that the view prints raw: the tainted one is among them
    const places = uses.slice(0, 3).map((use) => `${this.displayPath(use.file)}:${use.line} (${use.how})`);
    return `The view prints raw: ${places.join(", ")}${uses.length > 3 ? `, and ${uses.length - 3} more` : ""}.`;
  }

  protected config(): AnalyzerConfig {
    return {
      ruleId: "xss",
      severity: "high",
      confidence: "medium",
      isSource: isRequestSource,
      isSink: (node) => renderCall(node) !== undefined,
      // only the values the template prints raw can script the page
      sinkArgs: (sink) => {
        const call = renderCall(sink);
        if (!call) return [];
        const file = findViewTemplate(this.root, call.view);
        if (!file) return [];
        const dangerous: SyntaxNode[] = [];
        const found: UnsafeUse[] = [];
        for (const { key, value } of dataEntries(call.data)) {
          const use = viewUnsafeUse(file, key, this.root);
          if (!use) continue;
          dangerous.push(value);
          found.push(use);
        }
        if (found.length > 0) this.uses.set(sink.startIndex, found);
        return dangerous;
      },
      messageFor: (via) =>
        `User-controlled input ('${via}') is handed to a view that prints it without escaping.${DETAIL} ` +
        `A value with <script> runs in your visitors' browsers. Print it with the escaping tag (<%= %> in EJS, #{} in Pug, {{ }} in Handlebars), ` +
        `or escape it first (escape-html, DOMPurify for rich text).`,
    };
  }
}
