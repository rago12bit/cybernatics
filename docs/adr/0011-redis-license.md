# ADR-011: Pin Redis to 7.2 (the last BSD-licensed line)

Status: Accepted (2026-09-26, Week 22)

## Context
Generating THIRD_PARTY_LICENSES.md forced a look at every image the compose file runs. `redis:7-alpine` is a
floating tag and currently resolves to **7.4.11**. Redis 7.4 and later are no longer BSD-3-Clause: they are
RSALv2 / SSPLv1 (and Redis 8 adds AGPLv3). Neither RSALv2 nor SSPL is an OSI open-source license, and Bulwark's
license policy denies SSPL.

## Decision
Pin `redis:7.2-alpine`, the last BSD-3-Clause line, in `docker-compose.yml` and the README.

## Consequences
- **Existing dev stacks** that ran 7.4 hold an RDB file in the image's anonymous volume that 7.2 refuses to load
  ("Can't handle RDB format version 12"), so the container restarts in a loop. Redis here holds only queues and
  transient results: `docker compose rm -sfv redis && docker compose up -d` discards the volume and fixes it. Hit and
  fixed for real while making this change.
- The compose stack uses only what Bulwark needs from Redis (Celery broker, results, pub/sub, a list length for
  queue depth). All of it works on 7.2, and the full stack was brought up and a scan run against it.
- 7.2 receives fewer updates than current Redis. **Valkey** (BSD-3-Clause, Linux Foundation) is the maintained
  drop-in alternative and the better long-term answer; it was not adopted now because it changes the datastore
  and needs its own soak test.
- The license report lists the pin and the reason, and `scripts/gen-licenses.py --check` fails a build that
  introduces an unknown or network-copyleft license among the dependencies it can see (it cannot see image
  contents: the tool table is maintained by hand and checked against the Dockerfiles).
