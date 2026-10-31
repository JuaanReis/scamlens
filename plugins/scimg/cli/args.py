from argparse import ArgumentParser
from pathlib import Path

def parse_args(argv=None):
    parser = ArgumentParser(prog="scimg", description="Análise heurística experimental de imagens")
    parser.add_argument("target", nargs="?", type=Path)
    parser.add_argument("-f", "--file", type=Path)
    parser.add_argument("--k", type=float)
    parser.add_argument("--score-model", choices=("legacy", "grouped"))
    args = parser.parse_args(argv)
    if not (args.target or args.file) or (args.target and args.file):
        parser.error("Informe imagem por TARGET ou -f, não ambos")
    args.file = args.file or args.target
    return args
