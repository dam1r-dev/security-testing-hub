/**
 * Just enough SQL parsing to read migrations: split a file into statements (honouring comments, quoted
 * strings, quoted identifiers and `$$ ... $$` bodies) and pull qualified names / balanced clauses out of one.
 * This is not a SQL parser. It recognises the handful of statements the Supabase checks care about
 * (CREATE TABLE, ALTER TABLE ... ROW LEVEL SECURITY, CREATE POLICY, CREATE VIEW, CREATE FUNCTION, REVOKE)
 * and ignores everything else.
 */

export interface SqlStatement {
  /** Statement text with comments removed and whitespace collapsed. */
  text: string;
  /** 1-based line of the statement's first token. */
  line: number;
}

/** Splits `source` into statements on `;`, outside comments, strings, identifiers and dollar-quoted bodies. */
export function splitSql(source: string): SqlStatement[] {
  const statements: SqlStatement[] = [];
  let current = "";
  let line = 1;
  let startLine = 0;
  let i = 0;

  const flush = (): void => {
    const text = current.replace(/\s+/g, " ").trim();
    if (text !== "") statements.push({ text, line: startLine });
    current = "";
    startLine = 0;
  };
  const add = (chunk: string): void => {
    // A chunk is either one character or a quoted string / dollar body that starts at a visible character.
    if (startLine === 0 && /\S/.test(chunk)) startLine = line;
    current += chunk;
  };

  while (i < source.length) {
    const ch = source[i] as string;
    const next = source[i + 1];

    if (ch === "-" && next === "-") {
      while (i < source.length && source[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      let depth = 1;
      i += 2;
      while (i < source.length && depth > 0) {
        if (source[i] === "/" && source[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (source[i] === "*" && source[i + 1] === "/") {
          depth--;
          i += 2;
        } else {
          if (source[i] === "\n") line++;
          i++;
        }
      }
      current += " ";
      continue;
    }
    if (ch === "'" || ch === '"') {
      const quote = ch;
      let end = i + 1;
      while (end < source.length) {
        if (source[end] === quote) {
          if (source[end + 1] === quote) end += 2; // '' or "" escape
          else break;
        } else {
          end++;
        }
      }
      const chunk = source.slice(i, end + 1);
      add(chunk);
      line += (chunk.match(/\n/g) ?? []).length;
      i = end + 1;
      continue;
    }
    if (ch === "$") {
      const tag = /^\$[A-Za-z_]*\$/.exec(source.slice(i, i + 64));
      if (tag) {
        const close = source.indexOf(tag[0], i + tag[0].length);
        const end = close === -1 ? source.length : close + tag[0].length;
        const chunk = source.slice(i, end);
        add(chunk);
        line += (chunk.match(/\n/g) ?? []).length;
        i = end;
        continue;
      }
    }
    if (ch === ";") {
      flush();
      i++;
      continue;
    }
    if (ch === "\n") line++;
    add(ch);
    i++;
  }
  flush();
  return statements;
}

const IDENT = String.raw`(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)`;
/** `public.users`, `"public"."Users"`, `users` */
export const QUALIFIED_NAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;

export interface QualifiedName {
  schema: string;
  name: string;
}

export function parseQualified(raw: string, defaultSchema = "public"): QualifiedName {
  const parts = raw.split(".").map((p) => p.trim().replace(/^"|"$/g, "").toLowerCase());
  return parts.length >= 2 ? { schema: parts[parts.length - 2] as string, name: parts[parts.length - 1] as string } : { schema: defaultSchema, name: parts[0] as string };
}

export function keyOf(name: QualifiedName): string {
  return `${name.schema}.${name.name}`;
}

/** The text between the parenthesis that opens at `start` and its match (exclusive), or undefined. */
export function balanced(text: string, start: number): string | undefined {
  if (text[start] !== "(") return undefined;
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'") inString = !inString;
    if (inString) continue;
    if (ch === "(") depth++;
    if (ch === ")") {
      depth--;
      if (depth === 0) return text.slice(start + 1, i);
    }
  }
  return undefined;
}

/** `USING ( ... )` / `WITH CHECK ( ... )` -> the expression inside the parentheses. */
export function clause(text: string, keyword: RegExp): string | undefined {
  const match = keyword.exec(text);
  if (!match) return undefined;
  const open = text.indexOf("(", match.index + match[0].length - 1);
  return open === -1 ? undefined : balanced(text, open);
}

/** Replaces `$$ ... $$` bodies, so words inside a function body are not mistaken for its options. */
export function withoutDollarBodies(text: string): string {
  return text.replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, " $$ ");
}

/** Column names of a CREATE TABLE statement. */
export function columnNames(statement: string): string[] {
  const open = statement.indexOf("(");
  const body = open === -1 ? undefined : balanced(statement, open);
  if (!body) return [];
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) {
      parts.push(body.slice(last, i));
      last = i + 1;
    }
  }
  parts.push(body.slice(last));
  return parts
    .map((part) => part.trim())
    .filter((part) => part !== "" && !/^(constraint|primary|foreign|unique|check|like|exclude)\b/i.test(part))
    .map((part) => /^("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)/.exec(part)?.[1]?.replace(/"/g, "").toLowerCase() ?? "")
    .filter((name) => name !== "");
}
