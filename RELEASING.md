# Releasing

## One-time setup (do this before the first release)

1. **First publish must be manual** — `.github/workflows/publish.yml` can only
   publish *new versions* of packages that already exist on npm; it can't
   create a package for the first time (npm requires the first publish of a
   name to come from an authenticated `npm publish`, not CI). So:
   ```bash
   npm login          # in your own terminal — needs your npm account/2FA
   npm run build
   cd packages/scanner && npm publish && cd ../..
   cd packages/cli && npm publish
   ```
   Both packages are unscoped (`security-hub-scanner`, `security-hub`), so no
   `--access public` flag is needed — that flag only matters for `@scope/`
   packages, which default to private.

2. **Set up the automation token** (for `publish.yml` to handle future releases):
   - npmjs.com → Avatar → *Access Tokens* → *Generate New Token* → **Automation**
     (bypasses 2FA on publish, since it runs in CI with no interactive prompt).
   - GitHub repo → *Settings* → *Secrets and variables* → *Actions* → *New
     repository secret* → name it `NPM_TOKEN`, paste the token.

## Every subsequent release

1. Bump `"version"` in **both** `packages/scanner/package.json` and
   `packages/cli/package.json` to the same new version (and update
   `packages/cli/package.json`'s `"security-hub-scanner"` dependency version
   to match — they're released in lockstep, so keep them equal for now).
2. `npm install` at the repo root (refreshes `package-lock.json` with the new
   versions) and commit the version bump.
3. `git tag v<version>` (e.g. `v0.2.0`) and `git push --tags`, **or** just
   create a GitHub Release through the UI targeting that commit — either way,
   publishing a GitHub Release is what triggers `.github/workflows/publish.yml`.
4. Watch the *Publish to npm* workflow run. It builds, lints, tests, then
   publishes `security-hub-scanner` before `security-hub` (the CLI depends on
   the scanner by exact version, so the scanner has to land on the registry
   first).

If the workflow fails partway (e.g. scanner published but cli's tests then
fail), the scanner version is already live — don't reuse that version number
for a fix; bump again and re-release.
