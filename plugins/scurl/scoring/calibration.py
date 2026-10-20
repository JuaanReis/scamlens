"""Política de pontuação definida em scamLens/config.toml."""

from plugins.scurl import config

scoring_config = config["scoring"]
GROUPS = scoring_config["groups"]
CAPS = scoring_config["caps"]
DEFAULT_K = config["scanner"]["k"]
