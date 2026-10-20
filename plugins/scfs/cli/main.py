from .args import parse_args
from ..engine.main import run_engine
from json import dumps
import sys

def main():
    try:
        args = parse_args()
        scan, target = run_engine(source=args.file)
        if args.json:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            print(dumps({"scan": scan, "target": target}, ensure_ascii=False, indent=2))
        else:
            print({"scan": scan, "target": target})
        if scan["status"] in ("error", "inconclusive"):
            return 2
        return 0 if scan["result"]["verdict"] == "safe" else 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"ERROR {e}")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
