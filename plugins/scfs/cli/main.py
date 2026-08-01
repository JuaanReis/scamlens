from .args import parse_args
from ..engine.main import run_engine

def main():
    try:
        args = parse_args()
        result = run_engine(source=args.file, file_hint=args.file.suffix)
        print(result)
    except Exception as e:
        print(f"ERROR {e}")

if __name__ == "__main__":
    main()