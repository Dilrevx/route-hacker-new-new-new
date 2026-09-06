from __future__ import annotations

import gca.runtime_v2


def test_runtime_v2_is_importable_from_standalone_source_tree() -> None:
    assert gca.runtime_v2.__name__ == "gca.runtime_v2"
