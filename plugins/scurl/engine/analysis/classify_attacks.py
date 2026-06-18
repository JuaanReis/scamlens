from dataclasses import dataclass

@dataclass
class AttackClassification:
    attack_type: str
    confidence: float
    matched_rules: list[str]
    description: str

ATTACK_PROFILES: dict[str, dict] = {
    "phishing": {
        "description": "Tentativa de phishing — infraestrutura descartável imitando serviço legítimo.",
        "required": [],
        "weighted_rules": {
            "ssl_verify": (0.25, 0.3),
            "domain_age": (0.25, 0.5),
            "dns_verify": (0.15, 0.5),
            "rdap_field_incompleteness": (0.10, 0.5),
            "favicon_check": (0.15, 0.5),
            "external_script": (0.10, 0.5),
            "image_src_check": (0.10, 0.5),
            "password_input_check": (0.20, 0.5),
            "form_action_check": (0.15, 0.5),
        },
        "threshold": 0.30,
    },
    "credential_harvesting": {
        "description": "Coleta de credenciais — formulário de login em infraestrutura suspeita.",
        "required": ["password_input_check"],
        "weighted_rules": {
            "password_input_check": (0.40, 0.5),
            "form_action_check": (0.35, 0.5),
            "ssl_verify": (0.15, 0.3),
            "domain_age": (0.10, 0.5),
        },
        "threshold": 0.40,
    },
    "dga": {
        "description": "Domínio gerado algoritmicamente — infraestrutura automatizada ou botnet.",
        "required": ["random_domain_risk"],
        "weighted_rules": {
            "random_domain_risk": (0.35, 0.5),
            "random_subdomain_risk": (0.20, 0.5),
            "hyphen_risk": (0.15, 0.4),
            "num_ratio_risk": (0.15, 0.4),
            "name_server_diversity": (0.15, 0.5),
        },
        "threshold": 0.35,
    },
    "obfuscation": {
        "description": "Técnicas de obfuscação — payload ou destino deliberadamente obscurecido.",
        "required": [],
        "weighted_rules": {
            "base64_segment": (0.30, 0.5),
            "mix_encoding": (0.25, 0.5),
            "random_path_risk": (0.20, 0.5),
            "path_depth_risk": (0.15, 0.5),
            "fragment_risk": (0.10, 0.5),
        },
        "threshold": 0.30,
    },
    "open_redirect": {
        "description": "Open redirect — URL manipulada para redirecionar a destino arbitrário.",
        "required": ["query_contains_url"],
        "weighted_rules": {
            "query_contains_url": (0.40, 0.5),
            "redirect_check": (0.30, 0.5),
            "at_risk": (0.20, 0.5),
            "equal_risk": (0.10, 0.5),
            "query_no_value": (0.10, 0.5),
        },
        "threshold": 0.40,
    },
    "xss": {
        "description": "Cross-Site Scripting — injeção de script no contexto da página.",
        "required": ["xss_pattern"],
        "weighted_rules": {
            "xss_pattern":   (0.50, 0.5),
            "fragment_risk": (0.30, 0.5),
            "mix_encoding":  (0.20, 0.5),
        },
        "threshold": 0.50,
    },
    "infrastructure_abuse": {
        "description": "Abuso de infraestrutura — uso de IP direto, subdomínios anômalos ou WHOIS incompleto.",
        "required": [],
        "weighted_rules": {
            "ip_in_url": (0.40, 0.5),
            "subdomain_count": (0.20, 0.4),
            "random_subdomain_risk": (0.20, 0.5),
            "rdap_field_incompleteness": (0.15, 0.5),
            "name_server_diversity": (0.15, 0.5),
        },
        "threshold": 0.35,
    },
    "url_masking": {
        "description": "Mascaramento de URL — destino real oculto via técnicas de manipulação de parser.",
        "required": ["at_risk"],
        "weighted_rules": {
            "at_risk": (0.50, 0.5),
            "mix_encoding": (0.20, 0.5),
            "query_contains_url": (0.20, 0.5),
            "subdomain_count": (0.10, 0.4),
        },
        "threshold": 0.50,
    },
}

RULE_THRESHOLDS: dict[str, float] = {}
for _profile in ATTACK_PROFILES.values():
    for _rule, (_, _rule_threshold) in _profile["weighted_rules"].items():
        RULE_THRESHOLDS[_rule] = min(RULE_THRESHOLDS.get(_rule, 1.0), _rule_threshold)


def classify_attacks(heuristics: list[dict]) -> list[AttackClassification]:
    values = {h["name"]: h["value"] for h in heuristics}

    def active(rule: str, threshold: float) -> bool:
        return values.get(rule, 0) >= threshold

    results: list[AttackClassification] = []

    for attack_type, profile in ATTACK_PROFILES.items():
        if not all(active(r, 0.5) for r in profile["required"]):
            continue

        matched = []
        score = 0.0
        total_weight = sum(w for w, _ in profile["weighted_rules"].values())

        for rule, (weight, rule_threshold) in profile["weighted_rules"].items():
            if active(rule, rule_threshold):
                matched.append(rule)
                score += weight

        confidence = score / total_weight

        if confidence >= profile["threshold"]:
            results.append(AttackClassification(
                attack_type=attack_type,
                confidence=round(confidence, 3),
                matched_rules=matched,
                description=profile["description"],
            ))

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results