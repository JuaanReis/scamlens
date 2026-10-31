from sys import exit
from .args import parse_args
from .output import print_output
from plugins.scimg.engine.main import run_engine

def main(argv=None):
    try:
        args = parse_args(argv)
        scan = run_engine(args.file, k=args.k, score_model=args.score_model)
        print_output(scan)
        return 2 if scan.get("status") == "error" else 0
    except KeyboardInterrupt:
        return 130

if __name__ == "__main__":
    exit(main())
