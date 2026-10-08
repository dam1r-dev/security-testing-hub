// VULNERABLE: a secret behind a browser-exposed prefix (CWE-798 / CWE-200).
// Everything named NEXT_PUBLIC_* is copied into the JavaScript every visitor downloads,
// so a service-role key here gives every visitor full access to the database.
export function adminClient(createClient: (url: string, key: string) => unknown) {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL as string,
    process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY as string,
  );
}
