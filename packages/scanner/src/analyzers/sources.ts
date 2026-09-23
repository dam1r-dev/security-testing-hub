import { SyntaxNode } from "../parsers/utils";

// Express: req.params / req.query / req.body / req.cookies / req.headers,
// with or without a trailing property/index access.
const EXPRESS_MEMBER_PATTERN = /^req\.(params|query|body|cookies|headers)(\.\w+|\[[^\]]*\])?$/;

// Next.js App Router / Web Request API body readers: request.json(), req.text(), ...
const NEXT_BODY_READ_PATTERN = /^(req|request)\.(json|text|formData)$/;

// Chains ending in .searchParams.get(...) / .cookies.get(...) — covers
// `request.nextUrl.searchParams.get(...)`, `new URL(request.url).searchParams.get(...)`,
// and the common `const { searchParams } = new URL(request.url)` destructured form
// (by the time it's called, the "request" text is gone from the call site itself,
// so this intentionally doesn't require the chain to mention req/request).
const NEXT_ACCESSOR_SUFFIX_PATTERN = /(^|\.)(searchParams\.get|cookies\.get)$/;

function isExpressSource(node: SyntaxNode): boolean {
  if (node.type !== "member_expression" && node.type !== "subscript_expression") return false;
  return EXPRESS_MEMBER_PATTERN.test(node.text);
}

function isNextSource(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const calleeText = callee.text;
  if (NEXT_BODY_READ_PATTERN.test(calleeText)) return true;
  return NEXT_ACCESSOR_SUFFIX_PATTERN.test(calleeText);
}

/**
 * Matches user-controlled input from either an Express-style `req` object
 * (member/subscript access) or a Next.js App Router / Web Request-style
 * request (searchParams/cookies accessor calls, or a body-reading call like
 * `request.json()`). Shared by every taint-based analyzer so route-handler
 * conventions only need to be taught here once.
 */
export function isRequestSource(node: SyntaxNode): boolean {
  return isExpressSource(node) || isNextSource(node);
}
