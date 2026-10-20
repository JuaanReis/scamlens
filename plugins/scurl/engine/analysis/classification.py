from plugins.scurl import config

def classify(score: float) -> tuple[str, str]:

    if not 0 <= score <= 100:
        return "invalid", "unknown" 

    for band in config["scoring"]["classification"]:
        if score < band["below"]:
            return band["verdict"], band["risk"]

    return "malicious", "critical"
