# Bulwark API reference

_Generated from the OpenAPI 3.1.0 spec by `scripts/gen-api-docs.py`; do not edit._

All endpoints except `/healthz` need `Authorization: Bearer <BULWARK_API_TOKEN>`.
The WebSocket `/scans/{id}/ws` authenticates with a first message `{"token": "..."}`
and then streams `snapshot`, `tool.finished` and `scan.finished` events.

## `POST /scans`

Create Scan


## `GET /scans`

List Scans

- `limit` (query)

## `POST /scans/upload`

Upload Scan


## `GET /assets`

List Assets

- `limit` (query)

## `GET /assets/{asset_id}/overview`

Get Asset Overview

- `asset_id` (path, required)
- `fix_first_limit` (query)

## `POST /assets/web`

Register Web Asset


## `GET /assets/{asset_id}/verification`

Get Asset Verification

- `asset_id` (path, required)

## `POST /assets/{asset_id}/verify`

Verify Asset Endpoint

- `asset_id` (path, required)

## `POST /assets/{asset_id}/campaigns`

Start Dast Campaign

- `asset_id` (path, required)

## `GET /assets/{asset_id}/campaigns`

List Dast Campaigns

- `asset_id` (path, required)
- `limit` (query)

## `GET /assets/{asset_id}/issues`

List Issues

- `asset_id` (path, required)
- `severity` (query)
- `category` (query)
- `triage` (query)
- `sla` (query)
- `sort` (query)
- `limit` (query)
- `offset` (query)

## `GET /assets/{asset_id}/dependencies`

Get Dependencies

- `asset_id` (path, required)

## `GET /assets/{asset_id}/issues/{issue_id}`

Get One Issue

- `asset_id` (path, required)
- `issue_id` (path, required)

## `POST /assets/{asset_id}/issues/{issue_id}/triage`

Triage One Issue

- `asset_id` (path, required)
- `issue_id` (path, required)

## `POST /assets/{asset_id}/issues/bulk-triage`

Bulk Triage Issues

- `asset_id` (path, required)

## `GET /assets/{asset_id}/issues/{issue_id}/history`

Get Issue History

- `asset_id` (path, required)
- `issue_id` (path, required)

## `GET /scans/{scan_id}/guidance`

Get Guidance

- `scan_id` (path, required)
- `finding_id` (query, required)

## `POST /scans/{scan_id}/suggestion`

Create Suggestion

- `scan_id` (path, required)

## `POST /assets/{asset_id}/issues/{issue_id}/verified-fix`

Start Verified Fix

- `asset_id` (path, required)
- `issue_id` (path, required)

## `GET /assets/{asset_id}/issues/{issue_id}/verified-fix`

Get Verified Fix

- `asset_id` (path, required)
- `issue_id` (path, required)

## `POST /assets/{asset_id}/issues/{issue_id}/verified-fix/approve`

Approve Verified Fix

- `asset_id` (path, required)
- `issue_id` (path, required)

## `POST /assets/{asset_id}/issues/{issue_id}/verified-fix/reject`

Reject Verified Fix

- `asset_id` (path, required)
- `issue_id` (path, required)

## `POST /assets/{asset_id}/issues/{issue_id}/triage-assistant`

Create Triage Assessment

- `asset_id` (path, required)
- `issue_id` (path, required)

## `GET /assets/{asset_id}/issues/{issue_id}/triage-assistant`

Get Triage Assessment

- `asset_id` (path, required)
- `issue_id` (path, required)

## `POST /assets/{asset_id}/hypotheses/generate`

Generate Hypotheses

- `asset_id` (path, required)

## `GET /assets/{asset_id}/hypotheses`

List Hypotheses Endpoint

- `asset_id` (path, required)
- `status` (query)

## `POST /assets/{asset_id}/hypotheses/{hypothesis_id}/promote`

Promote Hypothesis Endpoint

- `asset_id` (path, required)
- `hypothesis_id` (path, required)

## `POST /assets/{asset_id}/hypotheses/{hypothesis_id}/dismiss`

Dismiss Hypothesis Endpoint

- `asset_id` (path, required)
- `hypothesis_id` (path, required)

## `GET /assets/{asset_id}/threat-model`

Get Threat Model Endpoint

- `asset_id` (path, required)

## `PUT /assets/{asset_id}/threat-model`

Save Threat Model Endpoint

- `asset_id` (path, required)

## `POST /assets/{asset_id}/threat-model/regenerate`

Regenerate Threat Model Endpoint

- `asset_id` (path, required)

## `GET /settings/retention`

Get Retention Settings Endpoint


## `PUT /settings/retention`

Save Retention Settings Endpoint


## `GET /plugins`

List Plugins Endpoint


## `PUT /plugins/{plugin_name}/allowlist`

Set Plugin Allowed Endpoint

- `plugin_name` (path, required)

## `GET /settings/integrations`

Get Integration Settings Endpoint


## `PUT /settings/integrations`

Save Integration Settings Endpoint


## `GET /assets/{asset_id}/attack-paths`

List Attack Paths Endpoint

- `asset_id` (path, required)

## `POST /assets/{asset_id}/copilot/conversations`

Start Conversation

- `asset_id` (path, required)

## `POST /assets/{asset_id}/copilot/conversations/{conversation_id}/messages`

Post Copilot Message

- `asset_id` (path, required)
- `conversation_id` (path, required)

## `GET /assets/{asset_id}/copilot/conversations/{conversation_id}/messages`

List Copilot Messages

- `asset_id` (path, required)
- `conversation_id` (path, required)

## `GET /risk/feeds`

Risk Feeds


## `GET /scans/{scan_id}`

Get Scan

- `scan_id` (path, required)

## `GET /scans/{scan_id}/findings`

Get Findings

- `scan_id` (path, required)
- `severity` (query)
- `category` (query)
- `tool` (query)
- `path` (query)
- `sort` (query)
- `limit` (query)
- `offset` (query)

## `GET /scans/{scan_id}/compare`

Compare Scans

- `scan_id` (path, required)
- `against` (query, required)

## `GET /scans/{scan_id}/cost`

Get Scan Cost

- `scan_id` (path, required)

## `GET /costs/summary`

Get Cost Summary

- `days` (query)

## `GET /scans/{scan_id}/export`

Export Scan

- `scan_id` (path, required)
- `format` (query)

## `POST /v2/ingest`

Ingest


## `GET /v2/imports/{import_id}`

Get Import

- `import_id` (path, required)

## `POST /v2/imports/{import_id}/confirm`

Confirm Import

- `import_id` (path, required)

## `POST /v2/imports/{import_id}/cancel`

Cancel Import

- `import_id` (path, required)

## `POST /v2/imports/{import_id}/revert`

Revert Import

- `import_id` (path, required)

## `GET /v2/tests/{test_id}/imports`

List Test Imports

- `test_id` (path, required)

## `GET /v2/projects/{project_id}/tests`

List Project Tests

- `project_id` (path, required)

## `GET /v2/parsers`

List Parsers


## `GET /v2/projects/{project_id}/dedup`

Dedup Overview

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/dedup/history`

Dedup History

- `project_id` (path, required)
- `source` (query)

## `POST /v2/projects/{project_id}/dedup/preview`

Dedup Preview

- `project_id` (path, required)

## `POST /v2/projects/{project_id}/dedup/apply`

Dedup Apply

- `project_id` (path, required)

## `POST /v2/mappings/analyze`

Analyze Sample


## `POST /v2/mappings/preview`

Preview Mapping


## `GET /v2/mappings`

List All


## `POST /v2/mappings`

Save Mapping


## `GET /v2/mappings/{mapping_id}`

Get One

- `mapping_id` (path, required)

## `POST /v2/cvss/v4`

Score Cvss


## `GET /v2/cwe`

Search Cwe

- `q` (query)
- `limit` (query)

## `GET /v2/projects/{project_id}/routes`

List Routes

- `project_id` (path, required)

## `POST /v2/projects/{project_id}/manual-findings`

Record Manual

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/manual-findings`

List Manual

- `project_id` (path, required)
- `issue_id` (query)

## `GET /v2/manual-findings/{manual_id}`

Get Manual

- `manual_id` (path, required)

## `POST /v2/manual-findings/{manual_id}/attachments`

Add Attachment

- `manual_id` (path, required)

## `POST /v2/attachments/{attachment_id}/link`

Attachment Link

- `attachment_id` (path, required)

## `GET /v2/attachments/{attachment_id}/download`

Download Attachment

- `attachment_id` (path, required)
- `token` (query, required)

## `GET /v2/connector-kinds`

Kinds


## `GET /v2/connectors`

List Connectors

- `project_id` (query)

## `POST /v2/connectors`

Create Connector


## `GET /v2/connectors/{connector_id}`

Get Connector

- `connector_id` (path, required)

## `PATCH /v2/connectors/{connector_id}`

Update Connector

- `connector_id` (path, required)

## `DELETE /v2/connectors/{connector_id}`

Delete Connector

- `connector_id` (path, required)

## `POST /v2/connectors/{connector_id}/run`

Run Connector

- `connector_id` (path, required)

## `GET /v2/projects/{project_id}/sla`

Get Sla

- `project_id` (path, required)

## `PUT /v2/projects/{project_id}/sla`

Put Sla

- `project_id` (path, required)

## Live progress (WebSocket)

`GET /scans/{scan_id}/ws` (not part of OpenAPI).
