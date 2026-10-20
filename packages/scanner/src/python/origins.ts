import { SyntaxNode } from "../parsers/utils";
import { Origin } from "./engine";

/**
 * The parameters of a web handler are the caller's input:
 *
 *   @app.route("/user/<uid>")                       # Flask: <uid> arrives as a parameter (as text, unless <int:uid>)
 *   @app.get("/items/{item_id}")                    # FastAPI: path, query and body values arrive as parameters (typed ones are converted)
 *   def show(request, pk): ...                      # Django: the URL's captures arrive after `request`
 *
 * A parameter typed `int`, `float`, `bool`, `UUID` or a date is converted by the framework before the function runs, so it cannot
 * carry SQL or a shell command; an untyped or `str` one can. Parameters the framework fills in itself (`Depends(...)`, `Request`, the
 * database session) are not the caller's.
 */

const ROUTE_DECORATOR = /^@[\w.]+\.(?:route|get|post|put|delete|patch|options|head|api_route|websocket|on_event)\s*\(/;
const FRAMEWORK_PARAMETER = new Set(["self", "cls", "request", "req", "response", "res", "background_tasks", "db", "session", "current_user", "user", "settings", "args", "kwargs"]);
const FRAMEWORK_TYPE = /^(?:Request|Response|HttpRequest|HTTPConnection|WebSocket|BackgroundTasks|Session|AsyncSession|Depends|Security|SecurityScopes|StarletteRequest|UploadFile|File)\b/;
const CONVERTED_TYPE_WORDS = /^(?:int|float|bool|UUID|uuid\.UUID|Decimal|datetime|date|time|timedelta|None|Optional|Union|List|list|Set|set|Tuple|tuple|Sequence|Literal|Annotated|Query|Path|Body|Header|Cookie|Form|ge|le|gt|lt|min_length|max_length)$/;

export interface ParameterInfo {
  name: string;
  /** Text of the annotation (`str`, `int | None`), if any. */
  type: string;
  /** Text of the default value (`Depends(get_db)`, `Query(...)`), if any. */
  defaultValue: string;
  /** `*args` / `**kwargs`. */
  variadic: boolean;
}

export function parametersOf(fn: SyntaxNode): ParameterInfo[] {
  const out: ParameterInfo[] = [];
  for (const parameter of fn.childForFieldName("parameters")?.namedChildren ?? []) {
    switch (parameter.type) {
      case "identifier":
        out.push({ name: parameter.text, type: "", defaultValue: "", variadic: false });
        break;
      case "default_parameter":
        out.push({ name: parameter.childForFieldName("name")?.text ?? "", type: "", defaultValue: parameter.childForFieldName("value")?.text ?? "", variadic: false });
        break;
      case "typed_parameter": {
        const name = parameter.namedChildren.find((c) => c.type === "identifier" || c.type === "list_splat_pattern" || c.type === "dictionary_splat_pattern");
        out.push({ name: name?.text.replace(/^\*+/, "") ?? "", type: parameter.childForFieldName("type")?.text ?? "", defaultValue: "", variadic: name?.type !== "identifier" });
        break;
      }
      case "typed_default_parameter":
        out.push({
          name: parameter.childForFieldName("name")?.text ?? "",
          type: parameter.childForFieldName("type")?.text ?? "",
          defaultValue: parameter.childForFieldName("value")?.text ?? "",
          variadic: false,
        });
        break;
      case "list_splat_pattern":
      case "dictionary_splat_pattern":
        out.push({ name: parameter.text.replace(/^\*+/, ""), type: "", defaultValue: "", variadic: true });
        break;
      default:
        break;
    }
  }
  return out.filter((p) => p.name !== "");
}

/** Is this annotation one the framework converts to (or validates as) a number, a date or a UUID? `Optional[int]`, `int | None`, `List[int]`. */
function isConvertedType(type: string): boolean {
  if (type === "") return false;
  const words = type.match(/[A-Za-z_][\w.]*/g) ?? [];
  return words.length > 0 && words.every((w) => CONVERTED_TYPE_WORDS.test(w));
}

export function decoratorsOf(fn: SyntaxNode): string[] {
  const parent = fn.parent;
  if (parent?.type !== "decorated_definition") return [];
  return parent.namedChildren.filter((c) => c.type === "decorator").map((d) => d.text);
}

/** The Flask converters in a route: `/u/<int:uid>/<name>` -> uid is a number, name is text. */
function flaskNumericNames(decorators: string[]): Set<string> {
  const numeric = new Set<string>();
  for (const decorator of decorators) {
    for (const m of decorator.matchAll(/<\s*(?:int|float|uuid)(?:\([^)]*\))?\s*:\s*(\w+)\s*>/g)) numeric.add(m[1] as string);
  }
  return numeric;
}

/**
 * The route's placeholders that are ONE URL segment: Flask `<name>`, `<string:name>`, `<int:name>`, `<uuid:name>`; FastAPI `{name}`. The router
 * refuses a "/" in them, so a file name taken from one cannot climb out of its directory. `<path:name>` and `{name:path}` take slashes.
 * `undefined` when the route has a placeholder that does.
 */
function segmentPlaceholders(decorators: string[]): Set<string> | undefined {
  const names = new Set<string>();
  for (const decorator of decorators) {
    if (!ROUTE_DECORATOR.test(decorator)) continue;
    for (const m of decorator.matchAll(/<\s*(?:(\w+)(?:\([^)]*\))?\s*:\s*)?(\w+)\s*>/g)) {
      if (m[1] === "path") return undefined;
      names.add(m[2] as string);
    }
    for (const m of decorator.matchAll(/\{\s*(\w+)\s*(?::\s*(\w+))?\s*\}/g)) {
      if (m[2] === "path") return undefined;
      names.add(m[1] as string);
    }
  }
  return names;
}

/** The names in this function that are the caller's from its first line. */
export function originsOf(fn: SyntaxNode): Origin[] {
  const decorators = decoratorsOf(fn);
  const parameters = parametersOf(fn);
  const origins: Origin[] = [];

  if (decorators.some((d) => ROUTE_DECORATOR.test(d))) {
    const numeric = flaskNumericNames(decorators);
    const segments = segmentPlaceholders(decorators);
    for (const p of parameters) {
      if (FRAMEWORK_PARAMETER.has(p.name) || numeric.has(p.name)) continue;
      if (/^(?:Depends|Security)\s*\(/.test(p.defaultValue) || FRAMEWORK_TYPE.test(p.type) || isConvertedType(p.type)) continue;
      if (/^(?:Query|Path|Body|Header|Cookie|Form)\s*\(/.test(p.defaultValue) && isConvertedType(p.type)) continue;
      // `def get(path: FileModel)` (flask-openapi3, spectree): the model named `path` holds the URL's placeholders
      const holdsPlaceholders = p.name === "path" && /^[A-Z]\w*$/.test(p.type);
      origins.push({ name: p.name, why: "route parameter", segment: !!segments && (segments.has(p.name) || holdsPlaceholders) });
    }
    return origins;
  }

  // Django: def view(request, pk, slug): the URL's captures come after `request`
  const first = parameters.find((p) => p.name !== "self" && p.name !== "cls");
  if (first && (first.name === "request" || first.name === "req") && /^(?:HttpRequest|Request|)$/.test(first.type.replace(/\s/g, ""))) {
    const after = parameters.slice(parameters.indexOf(first) + 1);
    for (const p of after) {
      if (isConvertedType(p.type)) continue;
      origins.push({ name: p.name, why: "URL parameter" });
    }
  }
  return origins;
}
