# 90-second demo video: script and shot list

Recording needs a person (screen capture and voiceover), so this is the plan, not the video. Record at
1440x900, dark system theme, browser zoom 100%, notifications off. Have the stack running
(`docker compose up -d`) and the API token on the clipboard before starting.

| Time | Screen | Say |
|---|---|---|
| 0:00-0:10 | http://localhost:3000, the sample report | "Security scanners each find a slice, and running four or five leaves you with duplicates and noise. Bulwark merges them into one list." |
| 0:10-0:25 | Scroll the numbers under the header | "This is a real scan: five scanners, raw findings on one side, unique findings after merging on the other." |
| 0:25-0:45 | Filter to High, click a finding, show the panel | "Open a finding: which scanners flagged it, each one's own severity, the code, the fix, and its CWE and OWASP category." |
| 0:45-1:00 | `j` / `k` through findings, then Export JSON | "Keyboard-friendly, and you can export exactly what you filtered." |
| 1:00-1:20 | /app, paste token, submit `https://github.com/OWASP/NodeGoat` | "Now a real repo. Each scanner runs sandboxed: no network, read-only." Cards fill in live. |
| 1:20-1:30 | Finished report, "771 raw to 463 unique" | "771 raw findings became 463. Open source, runs on your machine." |

Notes: NodeGoat takes about 80 seconds, so cut the wait in editing. Never show the token on screen.
Export as MP4; a GIF of the 0:25-0:45 section is the Week 8 README asset.
