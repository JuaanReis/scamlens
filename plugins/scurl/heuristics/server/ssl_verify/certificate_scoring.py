from math import exp, log
from datetime import date

TRUSTED_CAS = [
    "google trust services", "digicert", "sectigo", "comodo",
    "globalsign", "entrust", "wr2", "gr3", "gr4", "amazon",
    "microsoft", "apple", "cloudflare", "identrust",
]
LE_INDICATORS = ["let's encrypt", "letsencrypt", "e1", "e2", "r3", "r4", "r10", "r11"]


def f_age(age_days: int | None) -> float | None:
    """
    Avalia risco com base na idade do certificado desde a emissão.

    Certificados muito recentes são fortemente associados a phishing —
    atacantes emitem certificados descartáveis por demanda.

    Curva: decaimento exponencial (cert mais velho = menos risco).
    Constante de decaimento 120 dias: aos 90 dias já atinge ~0.47,
    aos 180 dias ~0.22 — alinhado com ciclo de renovação de Let's Encrypt.

    Retorna None se os dados forem inválidos (falha de parse).

    Exemplos:
        age_days=0   → 1.0  (emitido hoje — máximo risco)
        age_days=7   → 0.94
        age_days=30  → 0.78
        age_days=90  → 0.47
        age_days=180 → 0.22
        age_days=365 → 0.05
    """
    if age_days is None or age_days < 0:
        return None
    return exp(-age_days / 120)


def f_validity(validity_days: int | None) -> float | None:
    """
    Avalia risco com base no período de validade total do certificado.

    O padrão da indústria convergiu para 90 dias (Let's Encrypt, Google CA).
    Certificados muito curtos (<30 dias) indicam emissão de emergência ou
    infraestrutura automatizada descartável. Certificados muito longos
    (>398 dias) violam as diretrizes do CA/Browser Forum e são emitidos
    por CAs não-conformes ou comprometidas.

    Retorna None se os dados forem inválidos (falha de parse).

    Faixas:
        < 30 dias   → 0.9  (anormalmente curto)
        30–90 dias  → 0.1  (padrão moderno — baixo risco)
        91–398 dias → 0.2  (aceitável, levemente mais comum em phishing)
        > 398 dias  → 0.7  (viola CA/B Forum — CA não confiável ou comprometida)
    """
    if validity_days is None or validity_days <= 0:
        return None
    if validity_days < 30:
        return 0.9
    if validity_days <= 90:
        return 0.1
    if validity_days <= 398:
        return 0.2
    return 0.7


def f_expiry(days_until_expiry: int | None) -> float | None:
    """
    Penaliza certificados expirados ou com vencimento iminente.

    Sites legítimos renovam automaticamente (certbot, ACM, Cloudflare).
    Expiração iminente indica abandono, negligência ou infraestrutura
    descartável que não será renovada.

    Sem penalização acima de 30 dias — renovação nessa janela é normal.
    Abaixo disso, decaimento exponencial com constante 7 dias:
    aos 14 dias já atinge 0.13, aos 7 dias 0.37.

    Retorna None se os dados forem inválidos (falha de parse).

    Exemplos:
        days=0   → 1.0  (expirado)
        days=7   → 0.37
        days=14  → 0.13
        days=30  → 0.01 (limiar — acima disso retorna 0.0)
        days=31  → 0.0
    """
    if days_until_expiry is None:
        return None
    if days_until_expiry <= 0:
        return 1.0
    if days_until_expiry > 30:
        return 0.0
    return exp(-days_until_expiry / 7)


def f_issuer(issuer: str | None) -> float | None:
    """
    Avalia confiabilidade da CA emissora do certificado.

    CAs reconhecidas pelo CA/Browser Forum com histórico limpo recebem
    score zero. Let's Encrypt é legítima mas amplamente usada em phishing
    por ser gratuita e automatizada — penalização leve. CAs desconhecidas
    representam risco significativo.

    Retorna None se o campo estiver ausente (falha de parse ou cert inválido).

    Faixas:
        CA confiável (TRUSTED_CAS) → 0.0
        Let's Encrypt               → 0.3
        CA desconhecida             → 0.7
    """
    if not issuer or not issuer.strip():
        return None
    issuer_lower = issuer.lower()
    if any(ca in issuer_lower for ca in TRUSTED_CAS):
        return 0.0
    if any(ind in issuer_lower for ind in LE_INDICATORS):
        return 0.3
    return 0.7


def f_self_signed(is_self_signed: bool | None) -> float | None:
    """
    Detecta certificados autoassinados (issuer == subject).

    Certificados autoassinados não passam por validação de nenhuma CA
    confiável. Em contexto web são praticamente exclusivos de ambientes
    internos ou ataques MITM — nunca devem aparecer em sites públicos.

    Retorna None se o campo não estiver disponível.

    Valores:
        True  → 1.0 (autoassinado — máximo risco)
        False → 0.0
    """
    if is_self_signed is None:
        return None
    return 1.0 if is_self_signed else 0.0


def f_mismatch(hostname_mismatch: bool | None) -> float | None:
    """
    Verifica correspondência entre o hostname da requisição e o certificado.

    Mismatch indica erro grave de configuração, uso de certificado genérico
    em domínio errado, ou ataque MITM ativo. Browsers modernos bloqueiam
    conexões com mismatch — presença desse sinal em scan ativo é crítica.

    Retorna None se a verificação não foi possível.

    Valores:
        True  → 1.0 (mismatch — crítico)
        False → 0.0
    """
    if hostname_mismatch is None:
        return None
    return 1.0 if hostname_mismatch else 0.0


def f_san(san_count: int | None) -> float | None:
    """
    Avalia o número de Subject Alternative Names no certificado.

    SANs = 0 é inválido por RFC 2818 (hostname validation via CN está
    depreciado). SANs = 1 ou 2 é o padrão para domínios simples
    (ex: example.com + *.example.com). Contagens muito altas indicam
    certificados multi-domínio de CDNs compartilhadas — onde um único
    cert cobre centenas de clientes, comum em infraestrutura de phishing-as-a-service.

    Retorna None se o campo não estiver disponível.

    Faixas:
        0        → 0.8  (inválido por RFC)
        1–2      → 0.0  (padrão esperado)
        3–10     → 0.1  (multi-domínio legítimo)
        > 10     → 0.6  (CDN compartilhada — phishing-as-a-service)
    """
    if san_count is None:
        return None
    if san_count == 0:
        return 0.8
    if san_count <= 2:
        return 0.0
    if san_count <= 10:
        return 0.1
    return 0.6


def f_wildcard(san_list: list | None) -> float | None:
    """
    Detecta presença de entradas wildcard (*) nos SANs.

    Wildcards por si só são legítimos e comuns (*.example.com).
    A penalização é leve — wildcards ampliam o escopo do certificado
    e são usados em phishing para cobrir subdomínios gerados dinamicamente
    (ex: login.*.attacker.com). Sozinha essa métrica tem baixo sinal;
    peso no score final deve ser pequeno.

    Retorna None se a lista de SANs não estiver disponível.

    Valores:
        wildcard presente → 0.2
        ausente           → 0.0
    """
    if san_list is None:
        return None
    return 0.2 if any("*" in s for s in san_list) else 0.0


def f_org(organization: str | None) -> float | None:
    """
    Verifica presença do campo Organization (O=) no Subject do certificado.

    Certificados DV (Domain Validation) não incluem organização — são os
    mais baratos e rápidos de emitir, portanto os mais usados em phishing.
    Certificados OV/EV incluem organização validada manualmente pela CA.
    Ausência de organização não é prova de phishing, mas é consistente
    com infraestrutura descartável de baixo custo.

    Retorna None se o campo não estiver disponível no parse.

    Valores:
        organização presente → 0.0
        ausente              → 0.3  (DV — penalização leve)
    """
    if organization is None:
        return None
    return 0.0 if organization.strip() else 0.3


def f_sig_algorithm(algorithm: str | None) -> float | None:
    """
    Avalia o algoritmo de assinatura do certificado.

    SHA-1 está oficialmente depreciado desde 2017 e indica certificado
    antigo, mal configurado ou emitido por CA não confiável. MD5 é
    criticamente inseguro. SHA-256 e acima são o padrão atual.

    Retorna None se o campo não estiver disponível.

    Faixas:
        SHA256 / SHA384 / SHA512 / ECDSA → 0.0
        SHA1                              → 0.7
        MD5                               → 1.0
        desconhecido                      → 0.4
    """
    if not algorithm or not algorithm.strip():
        return None
    alg = algorithm.upper()
    if any(s in alg for s in ("SHA256", "SHA384", "SHA512", "ECDSA")):
        return 0.0
    if "SHA1" in alg:
        return 0.7
    if "MD5" in alg:
        return 1.0
    return 0.4