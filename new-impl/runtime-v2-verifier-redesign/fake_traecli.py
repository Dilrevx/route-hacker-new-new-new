#!/usr/bin/env python3

import json
import os
import stat
import sys
from pathlib import Path


def main() -> int:
    prompt = sys.stdin.read()
    result_path = Path(os.environ["RUNTIME_V2_RESULT_PATH"])
    workspace = Path(os.environ["RUNTIME_V2_WORKSPACE"])
    workspace.mkdir(parents=True, exist_ok=True)
    marker = workspace / "runtime-ready.txt"
    start = workspace / "runtime-start.sh"
    stop = workspace / "runtime-stop.sh"
    check = workspace / "runtime-check.sh"
    start.write_text(
        "#!/bin/sh\nprintf 'ready\\n' > runtime-ready.txt\n",
        encoding="utf-8",
    )
    stop.write_text("#!/bin/sh\nrm -f runtime-ready.txt\n", encoding="utf-8")
    check.write_text("#!/bin/sh\ntest -f runtime-ready.txt\n", encoding="utf-8")
    for path in (start, stop, check):
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    result_path.write_text(
        json.dumps(
            {
                "primary_image": "runtime-v2-smoke:latest",
                "launch": {
                    "type": "script",
                    "start": "runtime-start.sh",
                    "stop": "runtime-stop.sh",
                },
                "probes": [
                    {
                        "type": "command",
                        "command": ["./runtime-check.sh"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    final_message = None
    for index, value in enumerate(sys.argv):
        if value == "--output-last-message" and index + 1 < len(sys.argv):
            final_message = Path(sys.argv[index + 1])
            break
    if final_message:
        final_message.parent.mkdir(parents=True, exist_ok=True)
        final_message.write_text(
            f"Created runtime from prompt length {len(prompt)}.\n",
            encoding="utf-8",
        )
    print(json.dumps({"event": "completed", "marker": str(marker)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
