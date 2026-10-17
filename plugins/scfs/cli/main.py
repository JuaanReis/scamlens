import argparse
import json
from pathlib import Path
from .. import __version__
from ..config import Settings
from ..engine.main import run_engine
from ..heuristics import get_rules
from .output.formatter import render

def main(argv=None):
    parser = argparse.ArgumentParser(prog="scfs", description="Static heuristic executable scanner")
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--json", action="store_true", help="JSON report (array for multiple files)")
    parser.add_argument("--k", type=float, default=5.0)
    parser.add_argument("--score-model", choices=("grouped", "legacy"), default="grouped")
    parser.add_argument("--max-mib", type=int, default=64)
    parser.add_argument("--disable-rule", action="append", default=[])
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.list_rules:
        print("\n".join(r.name for r in get_rules()))
        return 0
    
    files = args.files
    if not files:

        try:
            files = [Path(input("scfs :: file path > ").strip().strip('"'))]
        except (EOFError, KeyboardInterrupt):
            return 2
    try:

        settings = Settings(k=args.k, score_model=args.score_model, max_file_bytes=args.max_mib*1024*1024,
                            disabled_rules=tuple(args.disable_rule))
        reports = [run_engine(path, settings=settings) for path in files]

    except ValueError as exc:
        parser.error(str(exc))

    if args.json:
        payload = [dict(scan=scan, target=target) for scan,target in reports]
        print(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, ensure_ascii=True))

    else:
        print("\n\n".join(render(scan,target) for scan,target in reports))

    if any(s['status'] in ('error', 'inconclusive') for s,t in reports):
        return 2
    
    return 1 if any(s['result']['verdict'] in ('suspicious', 'dangerous', 'malicious') for s,t in reports) else 0

if __name__ == '__main__':
    raise SystemExit(main())
