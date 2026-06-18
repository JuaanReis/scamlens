import sys
import json
from pathlib import Path

def save_output(file: str, data: dict, target: str | None = None):
    
    if target is not None:
        data = {
                "url": target, **data
            }

    if file == "-":
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return

    path = Path(file)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)