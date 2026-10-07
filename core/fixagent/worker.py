"""Temporal worker entrypoint for the verified-fix agent (plan §21.2). Start one with:

    python -m core.fixagent.worker

Connects to `BULWARK_TEMPORAL_ADDRESS` (default `localhost:7233`) and polls
`BULWARK_TEMPORAL_TASK_QUEUE` (default `bulwark-fixagent`) -- the same task queue the API
(`core/fixagent/client.py`) starts workflows on, so an operator only ever configures one name in
one place (`docker-compose.yml`'s `fixagent-worker` service sets both env vars explicitly, rather
than relying on the defaults matching by coincidence).
"""

from __future__ import annotations

import asyncio
import logging
import os

from temporalio.client import Client
from temporalio.worker import Worker

from core.fixagent.workflow import (
    VerifiedFixWorkflow,
    finish_run_activity,
    open_pr_activity,
    post_pr_result_activity,
    run_one_attempt_activity,
    set_awaiting_approval_activity,
)

log = logging.getLogger(__name__)

DEFAULT_ADDRESS = "localhost:7233"
DEFAULT_TASK_QUEUE = "bulwark-fixagent"


def task_queue() -> str:
    return os.environ.get("BULWARK_TEMPORAL_TASK_QUEUE", DEFAULT_TASK_QUEUE)


async def run_worker() -> None:
    address = os.environ.get("BULWARK_TEMPORAL_ADDRESS", DEFAULT_ADDRESS)
    client = await Client.connect(address)
    worker = Worker(
        client,
        task_queue=task_queue(),
        workflows=[VerifiedFixWorkflow],
        activities=[
            run_one_attempt_activity,
            set_awaiting_approval_activity,
            finish_run_activity,
            open_pr_activity,
            post_pr_result_activity,
        ],
    )
    log.info("fixagent worker polling %s on task queue %s", address, task_queue())
    await worker.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_worker())
