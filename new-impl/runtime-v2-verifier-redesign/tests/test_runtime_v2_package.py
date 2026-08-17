from __future__ import annotations

import route_hacker.runtime_v2


def test_runtime_v2_is_importable_from_standalone_source_tree() -> None:
    assert route_hacker.runtime_v2.__name__ == "route_hacker.runtime_v2"
