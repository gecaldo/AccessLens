# Reads the JSON snapshot and does a small format check before the audit starts.

import json
from pathlib import Path


def load_snapshot(path):
    snapshot_path = Path(path)

    with snapshot_path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if "users" not in data or "groups" not in data:
        raise ValueError("Snapshot needs both 'users' and 'groups' arrays.")

    return data
