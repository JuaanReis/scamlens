from colorama import init, Fore, Style

init(autoreset=True)

_COLOR_ENABLED = True
W = 40

def set_color(val: bool):
    global _COLOR_ENABLED
    _COLOR_ENABLED = val

def _c(color: str, text: str) -> str:
    if _COLOR_ENABLED:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

C_SECTION = Fore.CYAN + Style.BRIGHT
C_KEY     = Fore.WHITE
C_VAL     = Fore.YELLOW
C_OK      = Fore.GREEN
C_WARN    = Fore.YELLOW
C_DANGER  = Fore.RED + Style.BRIGHT
C_MUTED   = Style.DIM
RESET     = Style.RESET_ALL

def section(title: str):
    line = f"{'─' * 4} {title.upper()} {'─' * (30 - len(title))}"
    print(f"\n{_c(C_SECTION, line)}")

def row(key: str, value: str) -> str:
    return f"  {_c(C_KEY, key.ljust(16))}  {_c(C_VAL, value)}"

def enabled(val) -> str:
    return _c(C_OK, "ENABLED") if val else _c(C_MUTED, "DISABLED")

def yes_no(val) -> str:
    return _c(C_OK, "YES") if val else _c(C_DANGER, "NO")

def present(val) -> str:
    return _c(C_OK, "PRESENT") if val else _c(C_MUTED, "ABSENT")

def likely(val) -> str:
    return _c(C_WARN, "LIKELY") if val else _c(C_MUTED, "UNLIKELY")

def risk_label(score: float) -> str:
    if score >= 70:
        return _c(C_DANGER, "DANGEROUS")
    elif score >= 40:
        return _c(C_WARN, "SUSPICIOUS")
    return _c(C_OK, "SAFE")