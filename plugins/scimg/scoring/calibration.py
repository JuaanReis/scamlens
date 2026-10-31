"""Configuração de agrupamento e caps, paralela a scurl.scoring.calibration."""
from plugins.scimg import config
GROUPS = config.get("scoring", {}).get("groups", {})
CAPS = config.get("scoring", {}).get("caps", {})
DEFAULT_K = config.get("scanner", {}).get("k", 5.0)
