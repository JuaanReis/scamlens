from json import dumps
import sys
from ..config import Settings
from ..engine.main import run_engine
from .args import parse_args


def main():
    try:
        args = parse_args()
        expected = {key: value for key, value in {
            "merchant_name": args.expected_name,
            "amount": args.expected_amount,
            "location_host": args.expected_host,
        }.items() if value is not None}
        scan, target = run_engine(
            args.file if args.file is not None else args.payload,
            settings=Settings(disabled_rules=tuple(args.disable_rule)),
            expected=expected,
        )
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if args.json:
            print(dumps({"scan": scan, "target": target}, ensure_ascii=False, indent=2))
        else:
            print("scpix :: Pix/BR Code static scanner")
            print(":: Status", scan["status"])
            if scan["status"] == "error":
                print(":: Error", scan["error"]["message"])
            else:
                print(":: Type", target["pix"]["type"])
                print(":: Score", scan["result"]["score"])
                print(":: Verdict", scan["result"]["verdict"])
                print(":: Triggered", scan["stats"]["rules_triggered"], "/", scan["stats"]["rules_total"])
                for rule in scan["heuristics"]:
                    if rule["triggered"]:
                        print(" -", rule["name"], "::", rule["message"])
                for warning in scan["warnings"]:
                    print(" !", warning)
        if scan["status"] in ("error", "inconclusive"):
            return 2
        return 0 if scan["result"]["verdict"] == "no_structural_anomalies" else 1
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print("ERROR", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
