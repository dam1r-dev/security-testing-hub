// VULNERABLE: open redirect (CWE-601). The "next" target is not checked, so a link on this
// site can bounce visitors to any other site (a common post-login phishing trick).
import { redirect } from "next/navigation";

export async function GET(request: Request & { nextUrl: URL }) {
  const next = request.nextUrl.searchParams.get("next");
  redirect(next as string);
}
