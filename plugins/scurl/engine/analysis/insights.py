MESSAGES = {
    "form_action_check": "Formulário com senha aponta para outro domínio; confirme se esse destinatário é esperado.",
    "credential_cleartext": "Há campo de senha em uma página ou destino de formulário HTTP.",
    "credential_exfiltration": "Um script contém referência a senha, requisição e URL de outro domínio; o fluxo de dados não foi comprovado.",
    "safe_browsing": "O serviço de reputação retornou uma sinalização de ameaça.",
    "at_risk": "A URL contém userinfo antes do host; confira o domínio de destino.",
    "brand_subdomain": "Um domínio aparece como isca no subdomínio de outro.",
    "unicode_mixed_script": "O rótulo do domínio mistura alfabetos.",
    "xss_risk": "A URL contém padrões compatíveis com injeção de JavaScript; a execução não foi verificada.",
    "misleading_link": "Há link cujo texto mostra um domínio diferente do destino.",
    "ssl_score": "Foram observados indícios de problema no certificado TLS.",
}

def insights(heuristics, score):
    values = {h["name"]: h["value"] for h in heuristics}
    messages = [
        message for name, message in MESSAGES.items() if values.get(name, 0) >= 0.5
    ]

    if not messages:
        messages = (
            ["Poucos indicadores foram encontrados; isso não garante segurança."]
            if score < 25
            else ["A combinação dos indicadores justifica revisão do destino."]
        )
        
    return messages[:5]
