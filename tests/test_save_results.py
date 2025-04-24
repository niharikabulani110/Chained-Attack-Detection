from src.output import save_results
import json

def test_save_and_load_results(tmp_path):
    result = {
        "target": "http://localhost",
        "vulnerabilities": [{"type": "test", "detected": True}]
    }
    file = tmp_path / "results.json"
    save_results.save_results(result, str(file))

    with open(file, "r") as f:
        loaded = json.load(f)
    assert loaded == result
