// VULNERABLE: two Supabase auth mistakes in server code.
import { createClient } from "@supabase/supabase-js";

export async function GET() {
  const supabase = createClient(process.env.SUPABASE_URL as string, process.env.SUPABASE_ANON_KEY as string);

  // getSession() on the server trusts the cookie without asking Supabase to verify it.
  const { data } = await supabase.auth.getSession();

  // The role is read from user_metadata, which every user can edit from the browser.
  if (data.session?.user.user_metadata.role === "admin") {
    return Response.json({ secret: "admin data" });
  }
  return new Response(null, { status: 403 });
}
