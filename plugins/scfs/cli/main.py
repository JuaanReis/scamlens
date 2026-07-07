from .args import parse_args
from ..engine.main import run_engine

def main():
    try:
        args = parse_args()
        result = run_engine(source=args.file)
        print(result)
    except Exception:
        print(None)