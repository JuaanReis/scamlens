from argparse import ArgumentParser, Namespace
from plugins.scurl.cli.output.formatter import set_color
from plugins.scurl import config

def parse_args() -> Namespace | None:
    parse = ArgumentParser(description="scurl CLI version")
    parse.add_argument("--url", "-u", type=str)
    parse.add_argument("target", nargs="?")
    parse.add_argument("--verbose", "-v", action="store_true")
    scanner_config = config["scanner"]
    parse.add_argument("--threads", "-t", type=int, default=scanner_config["threads"])
    parse.add_argument("--output", "-o", type=str)
    parse.add_argument("--timeout", "-T", type=float, default=scanner_config["timeout"])
    parse.add_argument("-k", type=int, default=scanner_config["k"])
    parse.add_argument("--retries", "-r", type=int, default=scanner_config["retries"])
    parse.add_argument("--disable-color", "-dc", action="store_true")
    parse.add_argument("--cache", "-c", action="store_true", default=False)
    args = parse.parse_args()

    if args.url and args.target:
        parse.error("Use either positional URL or -u/--url, not both")

    if args.disable_color or not config["output"]["colors"]:
        set_color(False)

    args.url = args.url or args.target
    if not args.url:
        parse.error("Informe uma URL ou um arquivo QR")
    if args.threads < 1 or args.timeout <= 0 or args.k <= 0 or args.retries < 1:
        parse.error("threads, timeout, k e retries devem ser positivos")

    return args
