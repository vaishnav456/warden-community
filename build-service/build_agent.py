"""
Warden Build Service
---------------------
Polls endpt.build_requests for queued installer builds, cross-compiles
agent-go for Windows, packages the result, and uploads the zip to the
Warden server.

Runs in a plain Linux container (see Dockerfile) — cross-compiling Go needs
no Windows-specific tooling, unlike the old PyInstaller-based path.
  while True:
      fetch one queued build request
      if found: run the full build pipeline
      sleep POLL_INTERVAL_SEC

Usage:
    python build_agent.py

The build pipeline is in builder.py. Database access is in db.py.
"""

import time
import traceback
import logging

import config
import db
import builder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("build_agent")


def main() -> None:
    """
    Main polling loop for the build service.

    Polls db.next_queued_build() every POLL_INTERVAL_SEC seconds.
    When a queued build is found, calls builder.process_build(build_req).
    builder.process_build() handles all status updates and error reporting internally.

    Catches any unexpected exceptions from db calls to prevent the loop from crashing.
    Logs errors but always continues.
    """
    log.info("Warden Build Service started")
    log.info(f"Supabase: {config.SUPABASE_URL}")
    log.info(f"agent-go source: {config.AGENT_GO_SOURCE_DIR}")
    log.info(f"Output dir: {config.OUTPUT_DIR}")

    while True:
        try:
            db.requeue_stale_builds()
            build_req = db.next_queued_build()
            if build_req:
                log.info(f"Processing build request {build_req['id']}")
                builder.process_build(build_req)
        except Exception:
            log.error("Unexpected error in poll loop:\n" + traceback.format_exc())

        time.sleep(config.POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()
