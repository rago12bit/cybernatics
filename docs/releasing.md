# Releasing: tags, the VS Code Marketplace and the GitHub Marketplace

Tagging is done from here (see below); the Marketplace steps need your own accounts and tokens, so those are
yours to run. As of `v1.0.0`, neither Marketplace listing has been created.

`v0.1.0` and `v0.2.0` were tagged in git directly, without bumping `pyproject.toml`/`package.json` or giving
`v0.2.0` its own CHANGELOG entry (see the note at the top of the `v1.0.0` entry in CHANGELOG.md). `v1.0.0` is
the first release where the tag, the CHANGELOG and the package versions agree; keep them in sync from here on.

## 0. Before tagging

- CI is green on `main`, including the **Bulwark self-scan** workflow.
- `CHANGELOG.md`: move "Unreleased" under the new version, and bump `pyproject.toml`, `web/package.json` and
  `extensions/vscode/package.json` to match.
- Decide the names: the action's `name` in `action.yml` ("Bulwark security scan") and the extension's `publisher`
  (`bulwark-scan` in `extensions/vscode/package.json` is a placeholder). Marketplace names must be unique; neither has
  been checked.

```bash
git tag -a v1.0.0 -m "v1.0.0: all 26 weeks of the plan"
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
2. **Releases > Draft a new release**, choose the tag you want to publish (`v1.0.0` or later), tick **Publish this Action to the GitHub Marketplace**,
   pick a category (Security) and publish.
3. Also move a floating major tag so `uses: Rag2102/cyberimp@v0` works:

```bash
git tag -f v0 v1.0.0 && git push -f origin v0
```

4. Users then write `uses: Rag2102/cyberimp@v0` (or pin the commit SHA, which is safer).

Known limitations to state in the listing: the action has not been run on GitHub before its first release; it
rebuilds the scanner images on every run (2 to 4 minutes); fork pull requests cannot receive comments or SARIF.

## 3. After publishing

- Watch the first real pull request's run: expect surprises around Docker and permissions, and fix them in a patch
  release.
- Turn on **branch protection** requiring the Bulwark self-scan check, so "blocks on new HIGH findings" is enforced
  and not just displayed.
