from scamLens import get_settings, config, __version__

def is_production() -> bool:
    setting = get_settings()
    return setting.environment == "production"

def warning_aux_log() -> str:
    production = is_production()
    warnings = []

    server = config["server"]
    logs = config["logs"]
    cors = config["cors"]
    rate_limit = config["rate_limit"]
    cookies = config["cookies"]
    http = config["http"]
    rdap = config["rdap"]
    logging = config["logging"]
    scurl_scanner = config["scurl"]["scanner"]
    scurl_security = config["scurl"]["security"]
    scfs = config["scfs"]["scanner"]

    if __version__ == "0.0.0-npkg":
        warnings.append(
            "!! Package is not installed. Install ScamLens from PyPI. Read the documentation for setup instructions."
        )

        if production:
            warnings.append(
                "!! ScamLens is running in production mode without an "
                "installed package. This is not recommended."
            )

    if production and server["reload"]:
        warnings.append(
            "!! ScamLens is running in production mode with server reload "
            "enabled. This is not recommended."
        )

    if production and server["host"] in ("127.0.0.1", "localhost"):
        warnings.append(
            "!! ScamLens is running in production with a loopback server "
            "host. External clients may not be able to connect."
        )

    if server["workers"] < 1:
        warnings.append(
            "!! Server worker count is invalid. At least one worker is required."
        )

    if production and not logs["enabled"]:
        warnings.append(
            "!! ScamLens is running in production with logging disabled. "
            "This may make troubleshooting and auditing difficult."
        )

    if production and logs["level"].upper() == "DEBUG":
        warnings.append(
            "!! ScamLens is running in production with DEBUG logging enabled. "
            "This may generate excessive logs or expose diagnostic information."
        )

    if production and cors["enabled"]:
        if not cors["allow_origins"]:
            warnings.append(
                "!! CORS is enabled in production but no allowed origins "
                "are configured."
            )

        if "*" in cors["allow_origins"]:
            warnings.append(
                "!! CORS allows requests from all origins in production. "
                "This is not recommended."
            )

        if cors["allow_credentials"] and "*" in cors["allow_origins"]:
            warnings.append(
                "!! CORS credentials are enabled with a wildcard origin. "
                "Review the CORS configuration."
            )

    if production and not rate_limit["enabled"]:
        warnings.append(
            "!! Rate limiting is disabled in production. "
            "This may increase the risk of request abuse."
        )

    if rate_limit["enabled"]:
        if rate_limit["requests_per_minute"] <= 0:
            warnings.append(
                "!! Rate limiting is enabled with an invalid request limit."
            )

        elif rate_limit["requests_per_minute"] > 1000:
            warnings.append(
                "!! Production rate limit is unusually high. "
                "Review the configured request limit."
            )

    if production and not cookies["secure"]:
        warnings.append(
            "!! Secure cookies are disabled in production. "
            "This is not recommended."
        )

    if (
        production
        and cookies["samesite"].lower() == "none"
        and not cookies["secure"]
    ):
        warnings.append(
            "!! SameSite=None cookies are configured without Secure cookies. "
            "This configuration may not work as expected."
        )

    if production and not cookies["httponly"]:
        warnings.append(
            "!! HTTP-only cookies are disabled in production. "
            "This may expose authentication cookies to client-side scripts."
        )

    if not production and not cookies["secure"]:
        warnings.append(
            "!! ScamLens is running in development mode with secure cookies "
            "disabled. This may cause issues."
        )

    if not production and cookies["samesite"].lower() == "none":
        warnings.append(
            "!! ScamLens is running in development mode with SameSite=None "
            "cookies. This may cause issues."
        )

    if not production and not cookies["httponly"]:
        warnings.append(
            "!! ScamLens is running in development mode with HTTP-only "
            "cookies disabled. This may cause issues."
        )

    if production and not http["verify_ssl"]:
        warnings.append(
            "!! SSL certificate verification is disabled for HTTP requests "
            "in production. This is not recommended."
        )

    if http["max_redirects"] > 20:
        warnings.append(
            "!! HTTP redirect limit is unusually high. "
            "Review the configured maximum."
        )

    if http["timeout"] > 30:
        warnings.append(
            "!! HTTP timeout is unusually high. "
            "This may allow requests to remain pending for a long time."
        )

    if http["connect"] > http["timeout"]:
        warnings.append(
            "!! HTTP connect timeout exceeds the total HTTP timeout."
        )

    if http["read"] > http["timeout"]:
        warnings.append(
            "!! HTTP read timeout exceeds the total HTTP timeout."
        )

    if production and not rdap["verify"]:
        warnings.append(
            "!! RDAP TLS certificate verification is disabled in production. "
            "This is not recommended."
        )

    if rdap["max_concurrent_per_server"] > rdap["max_connections"]:
        warnings.append(
            "!! RDAP per-server concurrency exceeds the maximum "
            "connection pool."
        )

    if rdap["fallback_max_concurrent"] > rdap["max_connections"]:
        warnings.append(
            "!! RDAP fallback concurrency exceeds the maximum "
            "connection pool."
        )

    if production and logging["trust_proxy"]:
        warnings.append(
            "!! Proxy headers are trusted in production. Ensure the "
            "application is running behind a trusted reverse proxy."
        )

    if scurl_scanner["threads"] > 20:
        warnings.append(
            "!! SCURL scanner thread count is unusually high. "
            "This may increase resource usage."
        )

    if production and not scurl_scanner["cache"]:
        warnings.append(
            "!! SCURL result caching is disabled in production. "
            "Repeated scans may increase network usage."
        )

    if scurl_scanner["max_redirects"] > 20:
        warnings.append(
            "!! SCURL maximum redirects is unusually high. "
            "Review the configured limit."
        )

    if scurl_scanner["timeout"] > http["timeout"]:
        warnings.append(
            "!! SCURL timeout exceeds the global HTTP timeout."
        )

    if production and scurl_security["allow_private_ips"]:
        warnings.append(
            "!! SCURL is allowed to scan private IP addresses in production. "
            "This may expose internal network resources."
        )

    if production and scurl_security["allow_localhost"]:
        warnings.append(
            "!! SCURL is allowed to scan localhost in production. "
            "This may expose local services."
        )

    if scfs["max_file_size_bytes"] <= 0:
        warnings.append(
            "!! SCFS maximum file size is invalid."
        )

    if scfs["max_file_size_bytes"] > 500_000_000:
        warnings.append(
            "!! SCFS maximum file size is unusually high. "
            "This may increase memory and processing requirements."
        )

    if not warnings:
        return ""

    return "\n" + "\n".join(warnings) + "\n"