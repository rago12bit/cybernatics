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

## Live progress (WebSocket)

`GET /scans/{scan_id}/ws` (not part of OpenAPI).
