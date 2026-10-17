from sys import exit
from plugins.scurl.engine.main import run_engine
from plugins.scurl.cli.output import print_output
from plugins.scurl.cli.output.store_output import save_output
from .args import parse_args
from providers.database.connection import init_db

def main():
    try:
        args = parse_args()
        if args.cache:
            init_db()
        scan, target = run_engine(
            args.url,
            args.k,
            args.timeout,
            args.threads,
            args.retries,
            use_cache=args.cache,
            score_model=args.score_model,
        )
        if args.output == "-":
            save_output("-", scan, target)
        else:
            print_output(scan, target, args.verbose, None)
            if args.output:
                save_output(args.output, scan, target)
                print(f"\nSaída salva em {args.output}")
        if scan.get("status") == "error":
            return 2
        return (
            1
            if scan.get("result", {}).get("verdict")
            in ("suspicious", "dangerous", "malicious")
            else 0
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"FALHA {exc}")
        return 2

if __name__ == "__main__":
    exit(main())
