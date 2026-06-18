from .classify_attacks import classify_attacks, RULE_THRESHOLDS

def insights(heuristics: list[dict], score: float) -> list[str]:
    values = {h["name"]: h["value"] for h in heuristics}

    def active(rule: str, threshold: float | None = None) -> bool:
        t = threshold if threshold is not None else RULE_THRESHOLDS.get(rule, 0.5)
        return values.get(rule, 0) >= t

    attacks = classify_attacks(heuristics)
    attack_msgs = [a.description for a in attacks]

    patterns = [
        (
            ["domain_age", "ssl_verify", "dns_verify"],
            "Infraestrutura altamente suspeita: domínio recém-criado com SSL inválido e DNS anômalo — padrão comum em campanhas de phishing."
        ),
        (
            ["domain_age", "ssl_verify"],
            "Domínio recente com SSL suspeito — possível infraestrutura descartável."
        ),
        (
            ["domain_age", "dns_verify"],
            "Domínio novo com configuração DNS incomum — possível infraestrutura descartável."
        ),
        (
            ["random_domain_risk", "hyphen_risk", "num_ratio_risk"],
            "Domínio com alta entropia, hífens e números — perfil compatível com geração automática (DGA)."
        ),
        (
            ["random_domain_risk", "hyphen_risk"],
            "Domínio com alta entropia e hífens — possível geração automática."
        ),
        (
            ["random_domain_risk", "num_ratio_risk"],
            "Domínio com alta entropia e proporção elevada de números — indicativo de domínio gerado automaticamente."
        ),
        (
            ["random_domain_risk", "domain_age"],
            "Domínio com padrão aleatório recém-registrado — típico de campanhas descartáveis."
        ),
        (
            ["random_path_risk", "base64_segment"],
            "Segmento base64 em path aleatório — possível payload ofuscado."
        ),
        (
            ["random_path_risk", "path_depth_risk"],
            "Path profundo com segmentos aleatórios — estrutura projetada para evasão."
        ),
        (
            ["base64_segment", "mix_encoding"],
            "Base64 e encoding misto na mesma URL — múltiplas camadas de obfuscação."
        ),
        (
            ["query_contains_url", "mix_encoding"],
            "URL embutida na query com encoding misto — possível open redirect com obfuscação."
        ),
        (
            ["query_contains_url", "query_no_value"],
            "URL na query combinada com parâmetros vazios — estrutura típica de redirecionamento."
        ),
        (
            ["xss_pattern", "mix_encoding"],
            "Padrão XSS combinado com encoding misto — possível evasão de filtros."
        ),
        (
            ["xss_pattern", "fragment_risk"],
            "Padrão XSS no fragmento da URL — possível ataque DOM-based."
        ),
        (
            ["at_risk", "query_contains_url"],
            "Uso de '@' com URL na query — técnica clássica de mascaramento de destino."
        ),
        (
            ["at_risk", "mix_encoding"],
            "Uso de '@' com encoding misto — tentativa de confundir parsers de URL."
        ),
        (
            ["subdomain_count", "random_subdomain_risk"],
            "Múltiplos subdomínios com padrão aleatório — infraestrutura automatizada."
        ),
        (
            ["random_subdomain_risk", "domain_age"],
            "Subdomínio aleatório em domínio novo — possível phishing descartável."
        ),
        (
            ["form_action_check", "password_input_check"],
            "Formulário com campo de senha e ação suspeita — possível coleta de credenciais."
        ),
        (
            ["password_input_check", "ssl_verify"],
            "Campo de senha em página com SSL inválido — credenciais podem ser capturadas."
        ),
        (
            ["password_input_check", "domain_age", "form_action_check"],
            "Domínio novo com formulário de senha — possível credential harvesting."
        ),
        (
            ["favicon_check", "password_input_check"],
            "Favicon externo com campo de senha — possível clone de site legítimo."
        ),
        (
            ["image_src_check", "form_action_check"],
            "Imagens externas combinadas com formulário — possível clonagem de interface."
        ),
        (
            ["external_script", "favicon_check", "domain_age"],
            "Scripts e favicon externos em domínio novo — clone de site legítimo provável."
        ),
        (
            ["redirect_check", "random_domain_risk"],
            "Redirecionamento externo em domínio aleatório — possível evasão de detecção."
        ),
        (
            ["redirect_check", "domain_age"],
            "Redirecionamento externo em domínio novo — possível intermediário descartável."
        ),
        (
            ["redirect_check", "query_contains_url"],
            "Redirecionamento combinado com URL na query — cadeia de open redirect."
        ),
    ]

    patterns = sorted(patterns, key=lambda x: len(x[0]), reverse=True)

    MAX_TOTAL = 6
    pattern_slots = max(0, MAX_TOTAL - len(attack_msgs) - 1)

    used_rules: set[str] = set()
    pattern_msgs: list[str] = []

    for rules, message in patterns:
        if len(pattern_msgs) >= pattern_slots:
            break

        if any(r in used_rules for r in rules):
            continue

        if all(active(r) for r in rules):
            pattern_msgs.append(message)
            used_rules.update(rules)

    if score >= 70:
        score_msg = f"Pontuação crítica [{score:.1f}] — múltiplos sinais convergentes de ameaça."
    elif score >= 45:
        score_msg = f"Pontuação elevada [{score:.1f}] — sinais relevantes que justificam investigação."
    elif score >= 20:
        score_msg = f"Pontuação moderada [{score:.1f}] — alguns indicadores suspeitos detectados."
    else:
        score_msg = None

    msgs = attack_msgs + pattern_msgs
    if score_msg:
        msgs.append(score_msg)

    return msgs