# ADR-008: Product name "Bulwark"; distribution name `bulwark-scan`

Status: Proposed (2026-09-25); the owner may override

## Context
The design doc says to check name availability in Week 1 and to secure the GitHub organisation and
package names. Checked on 2026-09-25 against public registries:

| Name | PyPI | npm | GitHub |
|------|------|-----|--------|
| bulwark | taken (`bulwark` 0.6.1, an unrelated data-analysis package) | taken (empty placeholder) | taken (user, 0 repos) |
| bulwark-security | n/a | n/a | taken |
| kavach, palisade | taken | taken | taken |
| **bulwark-scan** | free | free | free |
| kavach-scan, usebulwark, bulwarkscan | free | free | free |

## Decision
Keep **Bulwark** as the product name (it is the name used throughout the project and UI) and use
**`bulwark-scan`** for the Python distribution, the npm scope/package and the GitHub organisation.
The installed CLI command stays `bulwark`. Import packages (`core`, `cli`, `api`) are unchanged.

## Consequences
- `pip install bulwark-scan` cannot be confused with the unrelated `bulwark` package.
- Nothing in the codebase depends on the distribution name, so renaming again is cheap.
- **Action for the owner:** register the `bulwark-scan` GitHub organisation, PyPI project and npm
  name soon (names are first-come). The VS Code Marketplace and trademark register were not checked.
