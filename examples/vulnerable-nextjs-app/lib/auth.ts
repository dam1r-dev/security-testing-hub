// Minimal stand-in for a NextAuth-style session helper.
export async function getServerSession() {
  return { user: { id: "someone" } };
}
