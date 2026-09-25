# Releasing: tags, the VS Code Marketplace and the GitHub Marketplace

These steps need your accounts and tokens, so they are yours to run. Nothing here has been done.

## 0. Before tagging

- CI is green on `main`, including the **Bulwark self-scan** workflow.
- `CHANGELOG.md`: move "Unreleased" under the new version.
- Decide the names: the action's `name` in `action.yml` ("Bulwark security scan") and the extension's `publisher`
  (`bulwark-scan` in `extensions/vscode/package.json` is a placeholder). Marketplace names must be unique; neither has
  been checked.

```bash
git tag -a v0.3.0 -m "M4: developer surfaces (VS Code extension, GitHub Action)"
git push --tags
```

## 1. VS Code Marketplace

1. Create a publisher at <https://marketplace.visualstudio.com/manage> and set `"publisher"` in
   `extensions/vscode/package.json` to its id.
2. Create an Azure DevOps personal access token with **Marketplace > Manage** scope (keep it out of the repo and
   out of chat).
3. Build, test, package and inspect:

```bash
cd extensions/vscode
npm ci && npm run typecheck && npm test && npm run build
npm run package            # writes bulwark-vscode.vsix (about 21 KB, 15 files)
npx vsce ls --no-dependencies   # review exactly what ships
```

4. Try it before publishing: in VS Code, **Extensions: Install from VSIX...**, open a folder, run
   **Bulwark: Scan Workspace**. This is the first time it runs in a real VS Code: check the Problems panel, the
   hover, the Quick Fix and the status bar by eye.
5. Publish: `npx vsce login <publisher>` then `npx vsce publish --no-dependencies`.

The extension needs the `bulwark` CLI and Docker on the user's machine; say so on the listing page (the README does).

## 2. GitHub Marketplace (the Action)

The repository root already holds `action.yml`, which is what the Marketplace requires.

1. Repository **Settings > General**: accept the GitHub Marketplace Developer Agreement (first time only) and
   enable two-factor authentication.
2. **Releases > Draft a new release**, choose tag `v0.3.0`, tick **Publish this Action to the GitHub Marketplace**,
   pick a category (Security) and publish.
3. Also move a floating major tag so `uses: Rag2102/cyberimp@v0` works:

```bash
git tag -f v0 v0.3.0 && git push -f origin v0
```

4. Users then write `uses: Rag2102/cyberimp@v0` (or pin the commit SHA, which is safer).

Known limitations to state in the listing: the action has not been run on GitHub before its first release; it
rebuilds the scanner images on every run (2 to 4 minutes); fork pull requests cannot receive comments or SARIF.

## 3. After publishing

- Watch the first real pull request's run: expect surprises around Docker and permissions, and fix them in a patch
  release.
- Turn on **branch protection** requiring the Bulwark self-scan check, so "blocks on new HIGH findings" is enforced
  and not just displayed.
