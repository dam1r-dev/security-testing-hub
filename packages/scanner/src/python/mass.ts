import { SyntaxNode, findNodes } from "../parsers/utils";
import { calleeText, callArguments } from "./engine";

/**
 * Mass assignment in Python: the WHOLE request body goes into a database write, so whatever fields the caller adds are written too
 * (`is_admin`, `role`, `balance`, `owner_id`):
 *
 *   User.objects.create(**request.POST.dict())          Django
 *   User(**request.json)                                SQLAlchemy / Flask
 *   User.query.filter_by(id=uid).update(request.json)   SQLAlchemy
 *   db.users.insert_one(request.get_json())             MongoDB
 *
 * Only the whole object counts (a single field, \`request.json["name"]\`, is fine). Not reported when the function validates the body
 * first (a Django form's \`cleaned_data\`, a serializer's \`validated_data\`, a schema's \`.load()\`) or filters it by an allowlist.
 */

const WHOLE_BODY = /^(?:self\.)?request\.(?:json|POST|data|form|get_json\(\)|get_data\(\)|body)$|^(?:self\.)?request\.(?:POST|form|json|data)\.(?:dict|to_dict|copy)\(\)$|^(?:self\.)?request\.get_json\([^)]*\)$/;
const VALIDATED = /cleaned_data|validated_data|\.is_valid\(|\.load\(|ALLOWED_FIELDS|allowed_fields|\bwhitelist\b|\ballowlist\b|\.pick\(|\bpick\(|if k in |if key in |for field in (?:\(|\[)/;
const WRITE_METHOD = /\.(?:create|get_or_create|update_or_create|bulk_create|update|insert_one|insert_many|replace_one|update_one|update_many|find_one_and_update|add|merge|insert)$/;
const MODEL_RECEIVER = /(?:^|\.)(?:objects|query|session|collection|db|Model|repository)\b|^[A-Z]\w*\.|^[A-Z]\w*$|\)\s*\.(?:update|create)$|filter(?:_by)?\(/;

export interface MassAssignment {
  call: SyntaxNode;
  body: string;
}

function isWhole(node: SyntaxNode, names: ReadonlySet<string>): boolean {
  let current = node;
  while (current.type === "parenthesized_expression" || current.type === "await") {
    const inner = current.namedChild(0);
    if (!inner) return false;
    current = inner;
  }
  if (current.type === "identifier") return names.has(current.text);
  if (current.type === "attribute" || current.type === "call") return WHOLE_BODY.test(current.text);
  if (current.type === "call") return false;
  return false;
}

export function massAssignments(fn: SyntaxNode): MassAssignment[] {
  if (!/request/.test(fn.text) || VALIDATED.test(fn.text)) return [];
  // `data = request.get_json()` / `data = dict(request.POST.items())`: a name that holds the whole body
  const names = new Set<string>();
  const assignments = findNodes(fn, (n) => n.type === "assignment");
  for (let pass = 0; pass < 3; pass++) {
    for (const a of assignments) {
      const left = a.childForFieldName("left");
      const right = a.childForFieldName("right");
      if (left?.type === "identifier" && right && !names.has(left.text) && (isWhole(right, names) || (right.type === "call" && /^(?:dict|copy\.copy)$/.test(calleeText(right)) && callArguments(right).positional[0] && isWhole(callArguments(right).positional[0] as SyntaxNode, names)))) names.add(left.text);
    }
  }
  const out: MassAssignment[] = [];
  for (const call of findNodes(fn, (n) => n.type === "call")) {
    const callee = call.childForFieldName("function");
    if (!callee) continue;
    const text = callee.text;
    const isModelConstructor = callee.type === "identifier" && /^[A-Z]\w*$/.test(text);
    const isWrite = WRITE_METHOD.test(text) && MODEL_RECEIVER.test(text.replace(/\.[a-z_]+$/, ""));
    if (!isModelConstructor && !isWrite) continue;
    const args = call.childForFieldName("arguments")?.namedChildren ?? [];
    for (const arg of args) {
      const spread = arg.type === "dictionary_splat" ? arg.namedChild(0) : undefined;
      const value = spread ?? (arg.type === "keyword_argument" ? undefined : arg);
      if (value && isWhole(value, names) && (spread || isWrite)) {
        out.push({ call, body: value.text });
        break;
      }
    }
  }
  return out;
}
