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

## `GET /assets/{asset_id}/issues`

List Issues

- `asset_id` (path, required)
- `severity` (query)
- `category` (query)
- `triage` (query)
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

## `GET /scans/{scan_id}/export`

Export Scan

- `scan_id` (path, required)
- `format` (query)

## Live progress (WebSocket)

`GET /scans/{scan_id}/ws` (not part of OpenAPI).
