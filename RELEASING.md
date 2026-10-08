# Releasing

Publishing uses npm's **Trusted Publishing (OIDC)** — GitHub Actions
authenticates to npm with a short-lived, workflow-scoped token, verified
against a trusted-publisher config you set per package on npmjs.com. No
`NPM_TOKEN` secret is stored anywhere. This isn't a preference — npm is
actively restricting static automation tokens that bypass 2FA (account
changes since Aug 2026, direct publishing from Jan 2027), so OIDC is the
supported path, not one option among several.

## One-time setup (do this before the first release)

Trusted publishing can't create a package for the first time — npm requires
a name's very first publish to be an authenticated, interactive `npm
publish` from a real npm account. So, in order:

1. **First publish, manually:**
   ```bash
   npm login          # in your own terminal — needs your npm account/2FA
   npm run build
   cd packages/scanner && npm publish && cd ../..
   cd packages/cli && npm publish
   ```
   Both packages are unscoped (`security-hub-scanner`, `security-hub`), so
   no `--access public` flag is needed — that only matters for `@scope/`
   packages, which default to private.

2. **Configure trusted publishing** — for **each** package
   (`security-hub-scanner` and `security-hub` separately, since this is
   per-package on npm):
   - npmjs.com → the package's page → *Settings* → *Publishing access* →
     add a **Trusted Publisher**.
   - Provider: GitHub Actions. Fill in: org/user `dam1r-dev`, repo
     `security-testing-hub`, workflow filename `publish.yml`. Leave
     environment blank (the workflow doesn't use one).
   - Once configured, go to the same *Publishing access* page and select
     **"Require two-factor authentication and disallow tokens"** — with
     OIDC handling CI, there's no remaining reason to allow a bypass-2FA
     token for this package at all.

No `NPM_TOKEN` GitHub secret is needed at any point — `publish.yml` already
just declares `permissions: id-token: write` and npm handles the rest.

## Every subsequent release

1. Bump `"version"` in **both** `packages/scanner/package.json` and
   `packages/cli/package.json` to the same new version (and update
   `packages/cli/package.json`'s `"security-hub-scanner"` dependency version
   to match — they're released in lockstep, so keep them equal for now).
2. `npm install` at the repo root (refreshes `package-lock.json` with the new
   versions) and commit the version bump.
3. Create a GitHub Release targeting that commit (via the UI, or `gh release
   create v<version>`) — publishing a Release is what triggers
   `.github/workflows/publish.yml`.
4. After the release, move the action's major tag so `uses: dam1r-dev/security-testing-hub@v0` picks it up:
   `git tag -f v0 <release commit> && git push -f origin v0` (only while the major version is 0).
5. Watch the *Publish to npm* workflow run. It builds, lints, tests, then
   publishes `security-hub-scanner` before `security-hub`.

If the workflow fails partway (e.g. scanner published but cli's tests then
fail), the scanner version is already live — don't reuse that version number
for a fix; bump again and re-release.
