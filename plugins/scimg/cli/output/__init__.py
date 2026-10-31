import json

def print_output(scan):
    print(json.dumps(scan, ensure_ascii=False, indent=2))
