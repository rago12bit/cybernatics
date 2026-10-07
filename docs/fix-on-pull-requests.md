# `/fix` on pull requests

A member comments `/fix` on a pull request. Bulwark replies with what the verified-fix agent would
try and the most it may spend. Nothing runs until someone allowed to replies `/fix confirm <code>`.
Each verified patch is then posted as a comment for a person to apply; Bulwark never pushes to the
branch. Design: [ADR-0059](adr/0059-mcp-server-and-fix-on-pull-requests.md). The agent itself:
[verified-fix-agent.md](verified-fix-agent.md).

## Set it up

1. The [GitHub App](github-app.md) is installed, with the **Issue comment** event subscribed (in
   addition to Pull request and Installation). Its "Pull requests: Read & write" permission covers
   reading the pull request and commenting.
2. The verified-fix agent runs: a Temporal server and `python -m core.fixagent.worker`, with a hosted
   model configured (`BULWARK_LLM_ENABLED=1` and a key). The worker needs the App's id and key too,
   to post results.
3. An admin links each person's GitHub username under **Settings → People and access → GitHub
   account**. Only an admin can: a person naming their own could name someone else's.

Limits you can set:

| Setting | Default | What it does |
|---|---|---|
| `BULWARK_FIX_TOKENS_PER_FINDING` | 60000 | The cap per finding; the preview's total is this times the findings. |
| `BULWARK_LLM_MAX_TOKENS_PER_ORG_MONTH` | 2000000 | The organization's monthly budget; every fix-agent token counts. |
| `BULWARK_LLM_COST_PER_1K_TOKENS_USD` | unset | When set, the preview shows a price. |
| `BULWARK_FIXAGENT_MAX_CONCURRENT_PER_ORG` | 3 | Runs at once per organization; a confirm that would pass it is refused. |

## Commands

The command must be the whole first line of a new comment (an edited comment never counts).

| Comment | What happens |
|---|---|
| `/fix` | A preview: up to 5 findings this pull request introduced (code, secrets, configuration), most severe first, and the token cap. A new preview replaces the last one. |
| `/fix confirm K7M2PQ9X` | Starts one run per finding, if everything below still holds. A code works once, for 24 hours. |
| `/fix cancel K7M2PQ9X` | Withdraws the preview. |

## Who may, and when

Checked on the preview and again on the confirm:

- the commenter is an owner, member or collaborator of the repository on GitHub, **and** an admin
  linked their GitHub account to an active person whose role on this project is Member or higher;
- the pull request is open and **not from a fork** -- the agent runs the pull request's code, which
  must never happen with the base repository's credentials;
- Bulwark has a finished scan of the commit the pull request is at;
- on confirm: the pull request has no new commits since the preview, the organization's budget left
  covers the cap, and it is under its concurrency limit.

Anything else gets a one-line reply saying why. A comment on a pull request Bulwark never scanned
gets no reply.

## What it does not do

- Push, merge or approve anything. A patch is a comment.
- Fix dependency findings (a version bump is not a code patch) or findings already on the base
  branch.
- Spend past the cap. The cap is checked before each model call, so the last call can pass it by
  that one call's size.
