# Writing a scanner plugin

Bulwark ships five scanners. If you need a sixth -- an internal tool, a commercial scanner, or an
open-source one Bulwark doesn't carry -- the Plugin SDK lets you add it as an ordinary, independently
versioned, pip-installable Python package. No fork, no change to Bulwark's own source.

A complete, real, installable example lives in the repository at
[`examples/bulwark-plugin-demo`](https://github.com/rago12bit/cybernatics/tree/main/examples/bulwark-plugin-demo)
-- every code sample on this page is adapted from it, and its own README is explicit about which
parts are a deliberate simplification for an example you can `pip install -e` with no CI pipeline of
your own, versus what a real plugin needs to do differently (mainly: publish and sign its own image,
rather than reusing one of Bulwark's).

## 1. Write a `ToolAdapter`

Exactly the same interface a built-in scanner implements (`core.adapters.base.ToolAdapter`):

```python
from pathlib import Path
from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.models import Finding

class MyAdapter(ToolAdapter):
    spec = ToolSpec(
        name="my-scanner",
        image="ghcr.io/you/my-scanner:1.0.0",   # pinned by digest for a real release
        categories=frozenset({"sast"}),
        languages=frozenset({"python"}),
    )

    def build_command(self, target: Path, output: Path, ctx: RepoContext | None = None) -> list[str]:
        return ["scan", str(target), "--output", str(output)]

    def parse(self, raw: bytes) -> list[Finding]:
        ...  # must never raise -- return [] for anything it can't make sense of
```

It runs through the exact same sandboxed `docker run` every built-in scanner does
(`--network=none --read-only --cap-drop=ALL --user=10001 ...`) -- there is no separate, looser path
for plugin code. If your tool's own `JsonAdapter`-shaped output helps, `core.adapters.helpers` (safe
parsing, `make_finding`) is available to a plugin exactly as it is to a built-in.

## 2. Prove it with the conformance kit

A plugin's own test suite runs the same four golden-file checks a built-in adapter's test does --
literally the same functions, not a lookalike reimplementation:

```python
from pathlib import Path
from core.plugins.conformance import run_conformance_kit
from my_plugin.adapter import MyAdapter

def test_bulwark_conformance() -> None:
    run_conformance_kit(MyAdapter(), Path(__file__).parent / "golden")
```

`golden/raw.json` is one real sample of your tool's raw output; `golden/expected.json` is the exact
`[f.to_dict() for f in adapter.parse(raw)]`, pretty-printed and committed. The kit checks that: it
matches that golden output exactly; `parse()` never raises on six shapes of garbage (empty output,
non-JSON, a record missing the keys it expects, ...) -- a scanner crashing or being killed mid-write
must degrade to "no findings from this tool," never take the whole scan down; every finding's path is
relative to the scanned target, never the sandbox's internal mount point; and every finding survives
a JSON round trip (how it's actually persisted).

## 3. Declare a `PluginManifest` and an entry point

```python
# my_plugin/plugin.py
from core.plugins.manifest import PluginManifest
from my_plugin.adapter import MyAdapter

manifest = PluginManifest(
    adapter=MyAdapter(),
    package_name="my-plugin",
    package_version="1.0.0",
    certificate_identity="https://github.com/you/my-plugin/.github/workflows/release.yml@refs/heads/main",
    certificate_oidc_issuer="https://token.actions.githubusercontent.com",
)
```

```toml
# pyproject.toml
[project.entry-points."bulwark.scanner_adapters"]
my-plugin = "my_plugin.plugin:manifest"
```

That's the whole packaging mechanism: `importlib.metadata.entry_points()`, the same standard
mechanism Python packaging already has, under the group name `bulwark.scanner_adapters`. Installing
your package (`pip install my-plugin`) next to Bulwark is enough for `core.plugins.registry.
discover_plugins()` to find it, with no change to Bulwark's own source. (`manifest` can also be a
zero-argument callable returning a `PluginManifest`, for a plugin that needs to build its adapter
lazily.)

## 4. Sign your image

`certificate_identity` and `certificate_oidc_issuer` are matched against the Sigstore keyless
signature on `adapter.spec.image` -- not a one-time check at install time, but re-verified by
`core.plugins.signing.verify_plugin_image` on *every* resolution, so a publisher's image drifting out
from under an already-allowlisted plugin is caught immediately, not whenever someone happens to
re-check.

If you publish from GitHub Actions, that's one step with [`cosign`](https://github.com/sigstore/cosign):

```bash
cosign sign ghcr.io/you/my-scanner:1.0.0   # keyless: signs with the workflow's own OIDC token
```

`certificate_identity` is that workflow's own job identity (e.g.
`https://github.com/you/my-plugin/.github/workflows/release.yml@refs/heads/main`) and
`certificate_oidc_issuer` is `https://token.actions.githubusercontent.com` -- proving the image was
built by *that* CI pipeline, not merely uploaded by whoever holds registry push rights. An unsigned
image, or one signed by a different identity than the manifest declares, fails verification and the
plugin simply won't run -- there's no partial-trust state.

The image then runs by the digest that signature covers (`ghcr.io/you/my-scanner:1.0.0@sha256:...`),
not by its tag again, so a tag moved between the check and the run cannot put an unverified image in
the sandbox. If your manifest already names a digest, the signature must be over that one.

## 5. Get allowlisted

Being installed and discovered is necessary but never sufficient: an organization must explicitly
turn a plugin on before any of its scans can use it.

```bash
curl localhost:8000/plugins -H "Authorization: Bearer $TOKEN"
curl -X PUT localhost:8000/plugins/my-plugin/allowlist -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"enabled": true}'
```

Turning a plugin on re-verifies its signature synchronously, right there -- a bad identity or an
unsigned image fails loudly at that moment (`422`), not silently at the next scan that happens to
request it. Turning one off never needs that check. Either way it's recorded in the audit log: who
allowed or revoked which plugin, and when.

## What this doesn't do yet

- **No severity mapping of your own.** A plugin with no row in `core/scoring/severity.py`'s matrix
  has every finding normalize to `INFO` regardless of your tool's own severity label. Registering a
  plugin's severities today still means a (small, reviewable) change to Bulwark's own source -- the
  plan's own Cut Order already names the whole Plugin SDK as the first thing to drop if time runs
  short, and this is exactly the rough edge that justifies that ranking.
- **No per-org private registry.** A plugin is whatever's installed in the worker's own Python
  environment; there's no mechanism yet for "org A can use this plugin, org B can't even see it
  exists" beyond the allowlist's own on/off switch.
- **The sandbox's resource limits are Bulwark's, not configurable per plugin.** A plugin needing more
  than 2 GB memory or a bigger `/tmp` than the sandbox default needs a change to the sandbox config,
  the same way a built-in like gosec did.
