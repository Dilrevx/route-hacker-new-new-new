from pathlib import Path
import runpy


def test_scripts_are_present():
    root = Path(__file__).resolve().parents[1] / "scripts"
    assert (root / "serve_traex_openai.py").is_file()
    assert (root / "materialize_iris_case.py").is_file()
    assert (root / "run_native_iris_case.py").is_file()
    assert (root / "run_native_iris_batch.py").is_file()


def test_batch_attempt_id_is_namespaced():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    assert module["safe_name"]("flash-a1") == "flash-a1"
    assert module["safe_name"]("v8:case") == "v8_case"
