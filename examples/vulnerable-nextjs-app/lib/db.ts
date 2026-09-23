// Minimal stand-in for a DB client, just so the analyzer sees a `.prepare()` call.
// Not a real database — this file has nothing to do with the vulnerabilities themselves.
export const db = {
  prepare(sql: string) {
    return {
      all(...params: unknown[]) {
        return [];
      },
    };
  },
};
