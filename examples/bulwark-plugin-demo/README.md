# bulwark-plugin-demo

A real, installable, third-party scanner-adapter package for Bulwark's Plugin SDK (Week 51 task 1,
plan §23) -- proof that discovery, the conformance kit, and sandboxed execution all work for code
outside this repository's own source tree, not just a demonstration that reads the same way.

## What's real here

- `src/bulwark_plugin_demo/plugin.py` exposes a `PluginManifest` through the
  `bulwark.scanner_adapters` entry point declared in `pyproject.toml`. Installing this package
  (`pip install -e examples/bulwark-plugin-demo`) makes `core.plugins.registry.discover_plugins()`
  find it immediately, with no change to Bulwark's own source.
- `golden/raw.json` + `golden/expected.json` are a real conformance-kit fixture:
  `core.plugins.conformance.run_conformance_kit(DemoAdapter(), Path("golden"))` passes against them,
  the same four checks (`assert_matches_golden`, `assert_never_raises_on_garbage`,
  `assert_paths_relative_to_target`, `assert_findings_survive_json_roundtrip`) a built-in adapter's
  own test runs.
- `DemoAdapter` runs through `core.runner.run_tool` exactly like a built-in -- proven in
  `tests/integration/test_plugin_sandbox_execution_live.py` by actually invoking Docker.

## What's a disclosed simplification, not a real plugin's shape

- **The image isn't this plugin's own.** `DemoAdapter.spec.image` is `bulwark/bandit:1.7.10` --
  Bulwark's own built-in Bandit image, reused because it's already proven to run correctly under the
  sandbox's strict flags (`--network=none --read-only --cap-drop=ALL --user=10001:10001`, etc.) and
  because building, pushing, and keylessly signing a brand-new image needs a real CI pipeline with
  OIDC access this example repo doesn't have. A real plugin publishes its own image.
- **Its declared Sigstore identity doesn't match its own image, on purpose.** `plugin.py` names
  `stefanprodan/podinfo`'s real release-workflow identity -- a well-known public image that genuinely
  carries a keyless Sigstore signature, used here only to prove `core.plugins.signing` calls real
  Sigstore infrastructure correctly (see `tests/integration/test_plugin_signing_live.py`). Verifying
  *this* manifest's declared identity against *this* adapter's actual image (`bulwark/bandit:1.7.10`,
  which carries no Sigstore signature at all) correctly fails -- demonstrated deliberately in
  `test_plugin_sandbox_execution_live.py`, not hidden as an inconvenient result.
- **No secret redaction.** The real `BanditAdapter` strips hardcoded-credential values out of its
  findings (`core/adapters/bandit.py`); this demo adapter does not -- a plugin's finding quality,
  including weaker secret handling than a built-in, is between the plugin author and whoever
  allowlists it, not something the SDK itself enforces today.
- **No severity mapping registered.** `demo-bandit-plugin` has no row in
  `core/scoring/severity.py`'s `MATRIX`, so every finding normalizes to `INFO`
  (`core.scoring.severity.normalize`'s own documented default) regardless of Bandit's real severity
  label. Registering a plugin's severities today still means editing Bulwark's own source -- a real
  gap the plan's own Cut Order already flags the whole Plugin SDK as the first thing to drop if time
  is short, and this is exactly the kind of rough edge that justifies that ranking.
