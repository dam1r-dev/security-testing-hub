// VULNERABLE: hard-coded secrets (CWE-798). Real projects leak keys exactly like this:
// the values below sit in the source, so they sit in every clone and every old commit.
// (Made-up values: none of these is a real credential.)
module.exports = {
  jwtSecret: "super-secret-key",
  adminPassword: "Adm1n!Pass#2024",
  databaseUrl: "postgres://shop_admin:Sup3rS3cret@db.shop-prod.internal-corp.io:5432/shop",
};
