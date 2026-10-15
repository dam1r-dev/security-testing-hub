import { ParsedFile } from "../parsers/ast-parser";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { ProjectContext } from "../taint/project";

/**
 * A webhook endpoint that believes what it is told. Payment providers call a URL of yours when someone pays or cancels;
 * the URL is public, so ANYONE can post a body saying `checkout.session.completed` and get a paid plan for free, unless
 * the handler checks the provider's signature on the raw body first (`stripe.webhooks.constructEvent(raw, signature, secret)`).
 *
 * Found by the provider's event names in a handler that never mentions verifying anything: a signature header, a
 * `constructEvent`-style call, svix, an HMAC or a function with "verify" in its name (which may live in another file: a
 * missed finding costs less than a wrong one on code that is fine).
 */

interface Provider {
  name: string;
  events: RegExp;
  advice: string;
}

const PROVIDERS: Provider[] = [
  {
    name: "Stripe",
    events: /["'`](?:checkout\.session\.(?:completed|async_payment_succeeded)|payment_intent\.succeeded|invoice\.(?:paid|payment_succeeded)|customer\.subscription\.(?:created|updated|deleted)|charge\.succeeded)["'`]/,
    advice:
      "Read the RAW body (`await req.text()`, or express.raw) and call `stripe.webhooks.constructEvent(rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)`; answer 400 when it throws.",
  },
  {
    name: "Lemon Squeezy",
    events: /["'`](?:order_created|subscription_created|subscription_payment_success|subscription_updated)["'`]/,
    advice: "Compute an HMAC-SHA256 of the raw body with your signing secret and compare it with the `X-Signature` header (crypto.timingSafeEqual) before trusting the event.",
  },
  {
    name: "Paddle",
    events: /["'`](?:transaction\.completed|subscription\.activated|transaction\.paid)["'`]/,
    advice: "Verify the `Paddle-Signature` header with the Paddle SDK's `webhooks.unmarshal` (or the documented HMAC) on the raw body before trusting the event.",
  },
];

// Anything that shows the handler checks where the call came from.
const VERIFICATION = /constructEvent|signature|svix|hmac|timingSafeEqual|verif(?:y|ied|ication)|unmarshal|webhooks?\.(?:verify|validate)|validateWebhook|Webhook\(/i;
// A file that is a request handler, not a constants file that lists event names.
const HANDLER =
  /\bexport\s+(?:async\s+)?function\s+(?:POST|action)\b|\bexport\s+const\s+(?:POST|action)\b|\b(?:app|router|server|api|fastify|route|r)\.(?:post|all)\s*\(|defineEventHandler|eventHandler\(|\bonRequest\s*\(|\bexport\s+default\s+(?:async\s+)?function\s+handler\b/;

export class WebhookSignatureAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, _context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    // A comment that says "no signature is checked" is not a check: look at the code only.
    // Blanked out in place (same length), so line numbers still match the file.
    const blank = (m: string): string => m.replace(/[^\n]/g, " ");
    const code = text.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/(^|[^:])(\/\/.*)$/gm, (_m, before: string, comment: string) => before + blank(comment));
    if (!HANDLER.test(code) || VERIFICATION.test(code)) return [];
    const findings: Finding[] = [];
    for (const provider of PROVIDERS) {
      const match = provider.events.exec(code);
      if (!match) continue;
      const before = text.slice(0, match.index);
      const line = before.split("\n").length;
      const column = match.index - before.lastIndexOf("\n");
      const lineText = text.split("\n")[line - 1] ?? "";
      findings.push({
        ruleId: "webhook-signature",
        severity: "high",
        confidence: "medium",
        message:
          `This ${provider.name} webhook handler acts on ${match[0]} but never verifies the signature. The URL is public: anyone can post a ` +
          `forged event and get what a payment would unlock (a paid plan, credits, a shipped order). ${provider.advice}`,
        location: { file: filePath, startLine: line, startColumn: column, endLine: line, endColumn: column + match[0].length },
        sourceSnippet: "(no signature check found in the handler)",
        sinkSnippet: lineText.trim().slice(0, 160),
      });
    }
    return findings;
  }
}
