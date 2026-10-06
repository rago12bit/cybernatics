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
- `priority` (query)
- `tag` (query)
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

## `GET /v2/projects/{project_id}/priority`

Get Priority

- `project_id` (path, required)

## `PUT /v2/projects/{project_id}/priority`

Put Priority

- `project_id` (path, required)

## `POST /v2/projects/{project_id}/priority/preview`

Preview Priority

- `project_id` (path, required)

## `GET /v2/checklists`

List Checklists


## `GET /v2/projects/{project_id}/engagements`

List Engagements

- `project_id` (path, required)

## `POST /v2/projects/{project_id}/engagements`

Create Engagement

- `project_id` (path, required)

## `GET /v2/engagements/{engagement_id}`

Get Engagement

- `engagement_id` (path, required)

## `PATCH /v2/engagements/{engagement_id}`

Patch Engagement

- `engagement_id` (path, required)

## `GET /v2/engagements/{engagement_id}/checklist`

Get Checklist

- `engagement_id` (path, required)

## `PUT /v2/engagements/{engagement_id}/checklist/{item_id}`

Put Checklist Item

- `engagement_id` (path, required)
- `item_id` (path, required)

## `POST /v2/engagements/{engagement_id}/close`

Close Engagement

- `engagement_id` (path, required)

## `GET /v2/engagements/{engagement_id}/report`

Get Report

- `engagement_id` (path, required)
- `format` (query)

## `GET /v2/issues/{issue_id}/retest`

Get Retest

- `issue_id` (path, required)

## `POST /v2/issues/{issue_id}/retest`

Step

- `issue_id` (path, required)

## `POST /v2/issues/{issue_id}/retest/run`

Run Targeted

- `issue_id` (path, required)

## `GET /v2/people`

List People


## `GET /v2/issues/{issue_id}/notes`

List Notes

- `issue_id` (path, required)

## `POST /v2/issues/{issue_id}/notes`

Add Note

- `issue_id` (path, required)

## `PATCH /v2/notes/{note_id}`

Edit Note

- `note_id` (path, required)

## `DELETE /v2/notes/{note_id}`

Delete Note

- `note_id` (path, required)

## `POST /v2/notes/{note_id}/attachments`

Add Note File

- `note_id` (path, required)

## `POST /v2/note-attachments/{attachment_id}/link`

Note File Link

- `attachment_id` (path, required)

## `GET /v2/mentions`

My Mentions


## `GET /v2/issues/{issue_id}/tags`

Issue Tags

- `issue_id` (path, required)

## `PUT /v2/issues/{issue_id}/tags`

Set Issue Tags

- `issue_id` (path, required)

## `GET /v2/projects/{project_id}/tags`

Project Tags

- `project_id` (path, required)

## `PUT /v2/projects/{project_id}/tags`

Set Project Tags

- `project_id` (path, required)

## `PUT /v2/projects/{project_id}/portfolio`

Assign Portfolio

- `project_id` (path, required)

## `GET /v2/portfolios`

List Portfolios


## `POST /v2/portfolios`

Create Portfolio


## `PUT /v2/portfolios/{portfolio_id}/tags`

Set Portfolio Tags

- `portfolio_id` (path, required)

## `GET /v2/risk-acceptance-policy`

Policy


## `POST /v2/projects/{project_id}/risk-acceptances`

Request Acceptance

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/risk-acceptances`

Project Acceptances

- `project_id` (path, required)
- `issue_id` (query)

## `GET /v2/risk-acceptances`

All Acceptances

- `state` (query)

## `GET /v2/risk-acceptances/{acceptance_id}`

One

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/approve`

Risk Acceptance Approve

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/reject`

Risk Acceptance Reject

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/withdraw`

Risk Acceptance Withdraw

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/expire`

Risk Acceptance Expire

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/reinstate`

Risk Acceptance Reinstate

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/extend`

Extend

- `acceptance_id` (path, required)

## `POST /v2/risk-acceptances/{acceptance_id}/attachments`

Add Proof

- `acceptance_id` (path, required)

## `GET /v2/rules/catalogue`

Rules Catalogue


## `GET /v2/rules/templates`

Rules Templates


## `GET /v2/rules`

List Rules

- `project_id` (query)

## `POST /v2/rules`

Create Rule


## `GET /v2/rules/{rule_id}`

Get Rule

- `rule_id` (path, required)

## `PUT /v2/rules/{rule_id}`

Update Rule

- `rule_id` (path, required)

## `DELETE /v2/rules/{rule_id}`

Delete Rule

- `rule_id` (path, required)

## `PUT /v2/rules/{rule_id}/enabled`

Enable Rule

- `rule_id` (path, required)

## `POST /v2/rules/test`

Test Draft


## `POST /v2/rules/{rule_id}/test`

Test Rule

- `rule_id` (path, required)

## `GET /v2/rule-runs`

List Runs

- `rule_id` (query)
- `status` (query)
- `limit` (query)

## `GET /v2/rule-runs/{run_id}`

Get Run

- `run_id` (path, required)

## `POST /v2/rule-runs/{run_id}/confirm`

Confirm Run

- `run_id` (path, required)

## `POST /v2/rule-runs/{run_id}/dismiss`

Dismiss Run

- `run_id` (path, required)

## `GET /v2/issues/{issue_id}/assignee`

Get Owner

- `issue_id` (path, required)

## `PUT /v2/issues/{issue_id}/assignee`

Set Owner

- `issue_id` (path, required)

## `PUT /v2/issues/{issue_id}/priority`

Set Priority

- `issue_id` (path, required)

## `GET /v2/notifications`

Inbox

- `unread` (query)

## `POST /v2/notifications/read`

Mark Read


## `GET /v2/notification-prefs`

My Prefs


## `PUT /v2/notification-prefs`

Save My Prefs


## `GET /v2/notification-prefs/team`

Team Prefs


## `PUT /v2/notification-prefs/team`

Save Team Prefs


## `GET /v2/issues/{issue_id}/watchers`

Get Watchers

- `issue_id` (path, required)

## `PUT /v2/issues/{issue_id}/watch`

Watch

- `issue_id` (path, required)

## `DELETE /v2/issues/{issue_id}/watch`

Unwatch

- `issue_id` (path, required)

## `GET /v2/projects/{project_id}/tickets`

Get Config

- `project_id` (path, required)

## `PUT /v2/projects/{project_id}/tickets`

Save Config

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/groups`

List Groups

- `project_id` (path, required)

## `POST /v2/projects/{project_id}/groups`

Make Group

- `project_id` (path, required)

## `GET /v2/groups/{group_id}`

Get Group

- `group_id` (path, required)

## `PUT /v2/issues/{issue_id}/group`

Set Issue Group

- `issue_id` (path, required)

## `GET /v2/issues/{issue_id}/ticket`

Get Ticket

- `issue_id` (path, required)

## `POST /v2/issues/{issue_id}/ticket`

File Ticket

- `issue_id` (path, required)

## `POST /v2/issues/{issue_id}/ticket/sync`

Sync Ticket

- `issue_id` (path, required)

## `GET /v2/calendar`

Get Calendar

- `from` (query, required)
- `to` (query, required)
- `project_id` (query)
- `kinds` (query)

## `GET /v2/components`

Search Components

- `purl` (query, required)
- `version` (query)
- `project_id` (query)

## `GET /v2/libraries`

List Libraries

- `q` (query)
- `ecosystem` (query)
- `limit` (query)

## `GET /v2/advisories`

List Advisories

- `state` (query)
- `q` (query)
- `kev` (query)
- `limit` (query)

## `GET /v2/advisories/{vuln_key}`

Get Impact

- `vuln_key` (path, required)

## `POST /v2/advisories/{vuln_key}/issues`

Create Issues

- `vuln_key` (path, required)

## `GET /v2/advisory-feeds`

Feeds


## `PUT /v2/projects/{project_id}/owner`

Set Owner

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/owner`

Get Owner

- `project_id` (path, required)

## `POST /v2/advisories/{vuln_key}/vex-drafts`

Draft Vex

- `vuln_key` (path, required)

## `POST /v2/vex/{statement_id}/confirm`

Confirm Vex

- `statement_id` (path, required)

## `POST /v2/vex/{statement_id}/reject`

Reject Vex

- `statement_id` (path, required)

## `POST /v2/vex/{statement_id}/withdraw`

Withdraw Vex

- `statement_id` (path, required)

## `GET /v2/projects/{project_id}/vex`

Project Vex

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/vex/openvex`

Project Openvex

- `project_id` (path, required)

## `GET /v2/projects/{project_id}/vex/cyclonedx`

Project Cyclonedx Vex

- `project_id` (path, required)

## `GET /v2/compliance/frameworks`

List Frameworks


## `GET /v2/compliance/frameworks/{framework_id}`

Get Framework

- `framework_id` (path, required)

## `GET /v2/projects/{project_id}/asvs`

Project Asvs

- `project_id` (path, required)
- `level` (query)

## `PUT /v2/projects/{project_id}/asvs/{requirement}`

Set Asvs Status

- `project_id` (path, required)
- `requirement` (path, required)

## `POST /v2/evidence-packs/preview`

Preview Pack


## `GET /v2/evidence-packs`

List Packs


## `POST /v2/evidence-packs`

Create Pack


## `GET /v2/evidence-packs/{pack_id}/bundle`

Get Pack Bundle

- `pack_id` (path, required)

## Live progress (WebSocket)

`GET /scans/{scan_id}/ws` (not part of OpenAPI).
