from argparse import ArgumentParser, Namespace, ArgumentError
from pathlib import Path

def parse_args() -> Namespace | None:
    parser = ArgumentParser()
    parser.add_argument("--file", "-f", type=Path)
    parser.add_argument("target", type=Path, nargs="?")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.file and args.target:
        parser.error("Use either positional FILE or -f/--file, not both")

    args.file = args.file or args.target
    if not args.file:
        parser.error("Informe um arquivo")

    return args
