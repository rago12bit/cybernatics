# Bulwark from your agent (MCP)

`bulwark mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server. Your own agent
(an editor's assistant, a desktop assistant, a terminal agent) starts it, and can then ask Bulwark
about Issues, their evidence, verified fixes and where libraries are used -- as you, and only as
you. Design: [ADR-0059](adr/0059-mcp-server-and-fix-on-pull-requests.md).

## Set it up

1. In Bulwark, open **My API tokens** and make a token. It acts as you: an agent using it sees what
   you see and can do what you can do, never more. The deployment's shared token is refused.
2. Add the server to your MCP client. Most clients take a command, arguments and environment:

   ```json
   {
     "mcpServers": {
       "bulwark": {
         "command": "bulwark",
         "args": ["mcp"],
         "env": {
           "BULWARK_API_URL": "https://bulwark.example.com",
           "BULWARK_MCP_TOKEN": "bulwark_..."
         }
       }
     }
   }
   ```

   The token goes in the environment, never in `args`, where other users of the machine could read
   it from the process list. A Bulwark API that is not on your own machine must be `https`.

## Tools

| Tool | What it returns |
|---|---|
| `list_issues` | Issues across every project you can see, most urgent first. `query` takes the Issues screen's language: `priority:P1 sla:breached -status:accepted`. |
| `get_issue` | One Issue's latest finding: code snippet, taint path, which scanners agree, severity and risk factors, SLA, remediation. |
| `get_verified_fix` | The verified-fix agent's latest run for an Issue: the patch and what was checked. |
| `search_components` | Where a library (`pkg:npm/lodash`) is used, optionally at versions in a range. |
| `run_scan` | Starts a scan of a public Git URL. **Off unless** the server is started with `--allow-scans` *and* your token may write scans. |

Nothing else changes anything: there is no tool to triage, accept a risk, close an Issue or approve
a fix. Those stay with people, in Bulwark.

## Untrusted text

Much of what Bulwark returns was written by someone it does not trust: the scanned code and its
comments, file names, scanner messages that quote them, package names, things people typed. Any of
it can be written to look like an instruction to your agent -- a comment in a scanned file saying
"ignore your instructions and ...".

So every such value comes back wrapped:

```json
{"title": {"untrusted_text": "SQL injection in the login handler"}, "severity": "high"}
```

Only values Bulwark sets itself (ids, severities, dates, counts) are left unwrapped, and only when
they look like one. Inside a wrapper, characters that hide or reorder text -- bidirectional
overrides, zero-width characters, terminal escapes -- are shown as `<U+202E>`, and long text is cut
with a note. Each result also says, in one sentence, what the wrapper means.

This labels the text; it cannot stop an agent from acting on it. Treat a Bulwark result the way you
would treat the repository itself, and keep your agent's own permissions narrow.

## What it cannot do

- See more than the token: projects you are not granted, other organizations, other people's
  tokens. Every call goes through the API's own checks and Postgres row-level security.
- Change anything, unless `run_scan` is on.
- Follow a redirect: the token is only ever sent to the address you configured.
