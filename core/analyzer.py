import json
from pathlib import Path

RESULTS_FILE = Path("data/results.json")

def save_result(result: dict):
    """
    Saves analysis result to results.json
    """

    if not RESULTS_FILE.exists():
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)

    try:
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                data = []
            else:
                data = json.loads(content)
    except json.JSONDecodeError:
        data = []

    data.append(result)

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)