from sys import exit
try:
    from plugins.scurl.engine.main import run_engine
    from plugins.scurl.cli.output import print_output
    from plugins.scurl.cli.output.store_output import save_output
    from .args import parse_args
    from providers.database.connection import init_db
except KeyboardInterrupt:
    print("FALHA keyboard_interrupt: Execução interrompida pelo usuário")
    exit(130)

def main():
    try:
        args = parse_args()
        cache = args.cache
        url = args.url
        start = None
        if cache:
            from time import time
            start = time()
            init_db()

        if args.output == "-":
            scan, target = run_engine(url, args.k, args.timeout, args.threads, args.retries, use_cache=cache)
            save_output("-", scan, target)
            return 2 if scan.get("status") == "error" else 0

        scan, target = run_engine(url, args.k, args.timeout, args.threads, args.retries, use_cache=cache)

        print_output(scan, target, args.verbose, start)

        if args.output:
            save_output(args.output, scan, target)
            print(f"\nSaída salva em {args.output}")
        return 2 if scan.get("status") == "error" else 0

    except KeyboardInterrupt:
        exit(130)

    except Exception as e:
        print(f"FALHA {str(e)}")
        exit(2)

if __name__ == "__main__":
    exit(main())
