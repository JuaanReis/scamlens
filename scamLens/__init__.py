from pathlib import Path
from dataclasses import dataclass
from os import environ, getenv
from functools import lru_cache
from dotenv import load_dotenv

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("scamlens")
except PackageNotFoundError:
    __version__ = "0.0.0-nferr"

try:
    _CONFIG_PATH = Path(__file__).parent / "config.toml"  
    with _CONFIG_PATH.open("rb") as f:
        config = tomllib.load(f)

    if not config:
        raise RuntimeError("config.toml is empty")

except FileNotFoundError:
    raise FileNotFoundError(f"TOML configuration file not found in {_CONFIG_PATH}")

except tomllib.TOMLDecodeError:
    raise RuntimeError(f"Error parsing the config.toml file {_CONFIG_PATH}")

@dataclass(frozen=True)
class Settings:
    email_admin: str
    password_admin: str
    jwt_secret: str
    google_safe_browsing_key: str
    environment: str = "production"

    @property
    def is_dev(self) -> bool:
        return self.environment == "development"

@lru_cache
def get_settings() -> Settings:
    load_dotenv() 
    env = getenv("SCAMLENS_ENV", "production")

    return Settings(
        email_admin = environ["EMAIL_ADMIN"],
        password_admin = environ["PASSWORD_ADMIN"],
        jwt_secret = environ["JWT_SECRET"],
        google_safe_browsing_key = environ["GOOGLE_SAFE_BROWSING_KEY"],
        environment = env,
    )