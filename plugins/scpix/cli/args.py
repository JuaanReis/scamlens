from argparse import ArgumentParser, Namespace
from pathlib import Path


def parse_args() -> Namespace:
    parser = ArgumentParser(description="scpix :: heuristic Pix / BR Code scanner")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--payload", "-p", help="Pix copia e cola (texto)")
    src.add_argument("--file", "-f", type=Path, help="Arquivo UTF-8 contendo Pix copia e cola")
    parser.add_argument("--json", action="store_true", help="Saída JSON estruturada")
    parser.add_argument("--expected-name", help="Nome de recebedor informado por fonte confiável")
    parser.add_argument("--expected-amount", help="Valor esperado com ponto decimal (ex.: 25.50)")
    parser.add_argument("--expected-host", help="Domínio de PSP esperado")
    parser.add_argument("--disable-rule", action="append", default=[], help="Desabilita uma regra nominal")
    return parser.parse_args()
