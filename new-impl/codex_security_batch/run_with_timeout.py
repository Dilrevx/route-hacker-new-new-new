#!/usr/bin/env python3
"""Run a command in its own process group with a wall-clock timeout."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-seconds", required=True, type=int)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    if not args.command or args.command[0] != "--" or len(args.command) == 1:
        parser.error("command must follow --")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("ab", buffering=0) as log_handle:
        process = subprocess.Popen(
            args.command[1:],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            log_handle.write(
                (f"\n[batch-timeout] case_id={args.case_id} "
                 f"timeout_seconds={args.timeout_seconds} at={now}; "
                 "terminating scan process group\n").encode("utf-8")
            )
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                log_handle.write(b"[batch-timeout] graceful termination expired; sending SIGKILL\n")
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            return 124


if __name__ == "__main__":
    raise SystemExit(main())
