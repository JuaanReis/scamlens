from .args import parse_args
from ..engine.main import run_engine
from sys import exit
from json import dumps

def main():
    try:
        args = parse_args()
        result = run_engine(source=args.file, file_hint=args.file.suffix)
        if isinstance(result, dict):
            print(dumps(result, ensure_ascii=True))
            return 2
        print(dumps({
            "status": "validated",
            "file": result.image_name,
            "size_bytes": result.image_size,
            "sha256": result.image_hash,
            "analysis_available": False
        }, ensure_ascii=True))
        return 0
    except Exception as e:
        print(f"ERROR {e}")
        return 2

if __name__ == "__main__":
    exit(main())
