from pathlib import Path
from dataclasses import dataclass
from os import environ, getenv
from functools import lru_cache
from dotenv import load_dotenv
from math import isfinite
from hashlib import sha256
from json import dumps
from urllib.parse import urlsplit

def scoring_fingerprint(config: dict) -> str:
    options = config["scurl"]
    payload = {name: options[name] for name in ("rules", "scoring", "security", "resources")}
    return sha256(dumps(payload, sort_keys=True, ensure_ascii=True).encode()).hexdigest()

def merge_config(base: dict, override: dict) -> dict:
    for name, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(name), dict):
            merge_config(base[name], value)

        else:
            base[name] = value

    return base

def validate_config(config: dict) -> None:
    positive = {
        "database": ("timeout",),
        "chat": ("max_message_length", "default_page_size", "max_page_size"),
        "validation": ("max_errors", "max_detail_length", "max_location_depth"),
        "domain": ("cache_size",),
        "uploads": ("avatar_max_bytes", "qr_max_bytes", "qr_max_pixels"),
        "auth": ("max_password_bytes", "max_name_length"),
        "rate_limit": ("requests_per_minute", "max_concurrent_scans"),
        "cookies": ("ttl_minutes", "ttl_days", "session_ttl_days"),
        "tls": ("timeout",),
        "logs": ("batch_size", "flush_interval", "queue_size", "max_bytes", "backup_count", "retention_days", "max_sessions"),
        "logs.database": ("batch_size", "flush_interval", "queue_size", "retention_days", "max_rows", "cleanup_interval"),
    }

    positive["scurl.scanner"] = (
        "k", "timeout", "threads", "retries", "max_workers", "max_rule_seconds"
    )

    positive["scurl.security"] = ("max_url_length",)
    positive["scfs.scanner"] = ("max_file_size_bytes", "k", "max_strings")

    integers = {
        "cache_size", "avatar_max_bytes", "qr_max_bytes", "qr_max_pixels",
        "max_password_bytes", "max_name_length", "requests_per_minute",
        "max_concurrent_scans", "threads", "retries", "max_workers", "max_url_length",
        "max_file_size_bytes", "max_strings",
        "max_message_length", "default_page_size", "max_page_size",
        "max_errors", "max_detail_length", "max_location_depth",
        "batch_size", "queue_size", "max_bytes", "backup_count", "retention_days", "max_sessions", "max_rows",
    }

    for section, names in positive.items():
        options = config
        for part in section.split("."):
            options = options[part]

        for name in names:
            value = options[name]
            if type(value) not in (int, float) or not isfinite(value) or value <= 0:
                raise ValueError(f"{section}.{name} deve ser um número positivo")
            
            if name in integers and type(value) is not int:
                raise ValueError(f"{section}.{name} deve ser inteiro")

    logs = config["logs"]
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    for name in ("level", "request_level", "scanner_level", "dependency_level", "console_level"):
        if not isinstance(logs[name], str) or logs[name].upper() not in valid_levels:
            raise ValueError(f"logs.{name} deve ser DEBUG, INFO, WARNING, ERROR ou CRITICAL")
        
    if not isinstance(logs["levels"], dict) or any(
        not isinstance(name, str) or not name or name == "root"
        or not isinstance(level, str) or level.upper() not in valid_levels
        for name, level in logs["levels"].items()
    ):
        raise ValueError("logs.levels deve mapear nomes de loggers para níveis válidos")
    
    for section in (logs["requests"], logs["database"]):
        for name in ("include_prefixes", "exclude_prefixes"):
            if name not in section:
                continue
            if not isinstance(section[name], list) or any(
                not isinstance(prefix, str) or not prefix.startswith("/") for prefix in section[name]
            ):
                raise ValueError(f"logs: {name} deve ser uma lista de caminhos iniciados por /")
            
    for section, names in ((logs, ("enabled", "console")),
                           (logs["requests"], ("enabled", "include_query", "include_user_agent", "include_referer")),
                           (logs["database"], ("enabled",))):
        if any(type(section[name]) is not bool for name in names):
            raise ValueError("Opções de ativação dos logs devem ser booleanas")

    cors = config["cors"]
    if any(type(cors[name]) is not bool for name in ("enabled", "allow_credentials")):
        raise ValueError("cors.enabled e cors.allow_credentials devem ser booleanos")
    
    if not isinstance(cors["allow_origins"], list):
        raise ValueError("cors.allow_origins deve ser uma lista de origens")
    
    for origin in cors["allow_origins"]:
        if not isinstance(origin, str):
            raise ValueError("cors.allow_origins deve conter somente strings")
        
        if origin == "*":
            if cors["allow_credentials"]:
                raise ValueError("CORS com credenciais exige origens explícitas")
            continue

        try:
            parsed = urlsplit(origin)
            port = parsed.port

        except ValueError:
            raise ValueError("Origem CORS inválida")
        
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment):
            
            raise ValueError("Origem CORS deve conter somente esquema, hostname e porta opcional")

    scanner = config["scurl"]["scanner"]
    if config["chat"]["default_page_size"] > config["chat"]["max_page_size"]:
        raise ValueError("chat.default_page_size não pode exceder chat.max_page_size")
    
    for name in ("cache_ttl_seconds", "max_redirects"):
        value = scanner[name]
        if type(value) is not int or value < 0:
            raise ValueError(f"scurl.scanner.{name} deve ser um inteiro não negativo")

    if scanner["score_model"] not in ("legacy", "grouped"):
        raise ValueError("scurl.scanner.score_model deve ser legacy ou grouped")

    scanner = config["scfs"]["scanner"]
    if not 0.1 <= scanner["k"] <= 20:
        raise ValueError("scfs.scanner.k deve estar entre 0.1 e 20")

    if scanner["max_file_size_bytes"] > 512 * 1024 * 1024 or scanner["max_strings"] > 100000:
        raise ValueError("Limites do scfs excedem 512 MiB ou 100000 strings")

    if scanner["score_model"] not in ("legacy", "grouped"):
        raise ValueError("scfs.scanner.score_model deve ser legacy ou grouped")

    if not isinstance(scanner["disabled_rules"], list) or any(not isinstance(name, str) for name in scanner["disabled_rules"]):
        raise ValueError("scfs.scanner.disabled_rules deve ser uma lista de nomes de regras")

    if config["auth"]["max_password_bytes"] > 72:
        raise ValueError("auth.max_password_bytes não pode exceder 72 (bcrypt)")

    rounds = config["auth"]["bcrypt_rounds"]
    if type(rounds) is not int or not 4 <= rounds <= 31:
        raise ValueError("auth.bcrypt_rounds deve ser um inteiro de 4 a 31")

    for value in [config["quota"]["anonymous_daily_limit"], *config["quota"]["plans"].values()]:
        if type(value) is not int or value < -1:
            raise ValueError("Cotas devem ser inteiros não negativos ou -1 para ilimitado")

    previous = 0
    for band in config["scurl"]["scoring"]["classification"]:
        threshold = band["below"]
        if type(threshold) not in (int, float) or not isfinite(threshold) or threshold <= previous:
            raise ValueError("Faixas de classificação devem ser crescentes")

        previous = threshold

    if previous <= 100:
        raise ValueError("Faixas de classificação devem cobrir o score 100")

    for name, value in config["scurl"]["scoring"]["caps"].items():
        if type(value) not in (int, float) or not isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"Limite de score inválido para {name}")

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("scamlens")
except PackageNotFoundError:
    __version__ = "0.0.0-npkg" # package is not installed

_PROJECT_PATH = Path(__file__).resolve().parent.parent / "pyproject.toml"
if _PROJECT_PATH.is_file():
    with _PROJECT_PATH.open("rb") as f:
        _project = tomllib.load(f).get("project", {})
    if _project.get("name") == "scamlens":
        __version__ = _project["version"]

try:
    BASE_DIR = Path(__file__).resolve().parent.parent
    _CONFIG_PATH = Path(__file__).parent / "config.toml"
    with _CONFIG_PATH.open("rb") as f:
        config = tomllib.load(f)

    if custom_config := getenv("SCAMLENS_CONFIG"):
        with Path(custom_config).open("rb") as f:
            merge_config(config, tomllib.load(f))

    if not config:
        raise RuntimeError("config.toml is empty")

except FileNotFoundError:
    raise FileNotFoundError(f"TOML configuration file not found in {_CONFIG_PATH}")

except tomllib.TOMLDecodeError:
    raise RuntimeError(f"Error parsing the config.toml file {_CONFIG_PATH}")

validate_config(config)

for name, value in config["paths"].items():
    path = Path(value).expanduser()
    config["paths"][name] = str(path if path.is_absolute() else BASE_DIR / path)

try:
    with (Path(__file__).parent / "logo_log.txt").open("r", encoding="utf-8") as f:
        logo = f.read()
except FileNotFoundError:
    logo = ""

@dataclass(frozen=True)
class Settings:
    email_admin: str
    password_admin: str
    jwt_secret: str
    google_safe_browsing_key: str
    auth_dummy_hash: str
    environment: str = "production"

    @property
    def is_dev(self) -> bool:
        return self.environment == "development"

@lru_cache
def get_settings() -> Settings:
    load_dotenv(BASE_DIR / ".env")
    env = getenv("SCAMLENS_ENV", "production")

    return Settings(
        email_admin = environ["EMAIL_ADMIN"],
        password_admin = environ["PASSWORD_ADMIN"],
        jwt_secret = environ["JWT_SECRET"],
        google_safe_browsing_key = environ["GOOGLE_SAFE_BROWSING_KEY"],
        auth_dummy_hash = environ["AUTH_DUMMY_HASH"],
        environment = env,
    )
