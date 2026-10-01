# v2.0.0 demo video: script and shot list

Recording needs a person (screen capture and voiceover) -- this is the plan, not the video (plan §33,
Week 52 task 3; the video itself is explicitly left to you). Record at 1440x900, dark system theme,
browser zoom 100%, notifications off. Have the full stack running (`docker compose up -d`), the API
token on the clipboard, and a GitHub App or test repo ready if you show the verified-fix agent.

| Time | Screen | Say |
|---|---|---|
| 0:00-0:15 | The new homepage (`/`), let the replay run | "This is a real scan of OWASP Juice Shop -- five scanners, watched as they finish, not a stats block." |
| 0:15-0:30 | Scroll to "271 unique, 287 raw", severity bars | "287 raw findings became 271 after merging duplicates across scanners -- the same correlation v1.0 shipped, still doing the work." |
| 0:30-0:50 | Open a finding with a taint path attached | "This isn't just 'Semgrep found an eval() call' -- the taint engine confirmed the argument actually flows from this HTTP request. That's new in v2." |
| 0:50-1:10 | `/app`, open a project, click into Hypotheses or the Copilot panel | "An LLM layer sits on top now: a triage assistant that flags likely false positives, a hypotheses lane for authorization flaws pattern matching can't see, and a project-scoped copilot you can ask questions." |
| 1:10-1:35 | The verified-fix agent: propose a patch, show it rerun the rule + scanners + tests | "The flagship feature: it doesn't just suggest a fix. It applies it, reruns the triggering rule, reruns every scanner, runs your own tests, and only then opens a real PR for a human to approve." |
| 1:35-1:50 | Asset verification -> a DAST campaign view | "And now it isn't just static analysis -- authorized DAST, behind ownership verification and a scope-enforcing proxy, confirms some of this is exploitable at runtime, not just present in the code." |
| 1:50-2:05 | `bulwark precommit install`, a terminal, a blocked commit | "Catch a secret before it's even committed -- native, no Docker, fast enough for every commit." |
| 2:05-2:15 | `docs/` site homepage (`mkdocs serve`) | "And it's documented like a real project now, not just a README." |
| 2:15-2:25 | Close on the GitHub repo / release page | "Open source, Apache-2.0. v2.0.0, and the evaluation numbers -- including what we don't claim yet -- are public too." |

## Notes

- Juice Shop's own scan (homepage replay) is pre-captured, honestly labelled "replaying" on-screen --
  say "a real scan, replayed" in the voiceover too, not "scanning live right now."
- The verified-fix agent segment needs `docker compose --profile fixagent up -d` and a real
  `ANTHROPIC_API_KEY` -- rehearse this one once before recording; it's the slowest, most moving-parts
  part of the stack.
- Never show a real API token, webhook secret, or `.env` file on screen.
- Export as MP4. A 15-second GIF of the taint-path finding (0:30-0:50) is a good README/launch-post
  asset, the same way the Week 8 filter GIF was for v1.
