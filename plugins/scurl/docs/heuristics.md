# scurl — Referência de Heurísticas

## Visão Geral

O scurl executa um pipeline de heurísticas independentes organizadas em três categorias: **URL**, **HTML** e **SERVER**. Cada heurística analisa um aspecto do alvo e produz um `ResultBase`.

### Contrato ResultBase

```python
@dataclass
class ResultBase:
    value: float        # valor bruto da análise
    normalized: float   # score de risco [0.0 – 1.0], ou None se não aplicável
    details: dict       # dados coletados, variáveis por heurística
```

`normalized = None` significa que o sinal não é aplicável ao alvo — a heurística é excluída do cálculo de score. É diferente de `0.0`, que indica risco confirmado como baixo.

---

## Registro de Heurísticas

As heurísticas são registradas via decorator `@register`:

```python
@register(name="...", category="...", severity="...", weight=..., tags=[...])
def nome_da_regra(structure: dict) -> ResultBase:
    ...
```

| Campo | Tipo | Descrição |
|---|---|---|
| `name` | `str` | Identificador único da regra |
| `category` | `str` | `url`, `html` ou `server` |
| `severity` | `str` | `low`, `medium` ou `high` |
| `weight` | `float` | Peso no cálculo de score final |
| `tags` | `list[str]` | Metadados de classificação |

---

## Categorias

| Categoria | Foco |
|---|---|
| `url` | Análise estrutural da URL: domínio, path, query, encoding, caracteres |
| `html` | Comportamento da página: formulários, scripts, recursos externos, redirecionamentos |
| `server` | Infraestrutura: SSL, DNS, idade do domínio, RDAP, reputação |

---

## Heurísticas de URL

### `hyphen_risk`
**Peso:** 2.5 | **Severidade:** medium

Conta hífens no domínio registrado. Hífens são frequentemente usados para criar domínios que imitam marcas legítimas (ex: `pay-pal.com`).

- `value`: contagem de hífens
- `normalized`: `normalize_counter(count, threshold=2)` — `None` se count = 0

**details:** `{hyphen_count}`

---

### `at_risk`
**Peso:** 4.0 | **Severidade:** high

Detecta o caractere `@` na URL. Browsers ignoram tudo antes do `@`, permitindo ocultar o destino real (ex: `paypal.com@malicioso.com` → acessa `malicioso.com`).

- `value`: contagem de `@`
- `normalized`: `normalize_counter(count, threshold=1)` — qualquer presença é suspeita

**details:** `{at_count}`

---

### `equal_risk`
**Peso:** 2.0 | **Severidade:** medium

Conta caracteres `=` no path, domínio e subdomínios. Concentração de `=` fora da query string indica ofuscação ou tentativa de injeção.

- `value`: contagem de `=`
- `normalized`: `min(count / 3, 1.0)` — `None` se count = 0

**details:** `{equal_count}`

---

### `num_ratio_risk`
**Peso:** 2.0 | **Severidade:** medium

Calcula a proporção de dígitos no domínio ou subdomínio mais longo. Alta proporção numérica é comum em domínios gerados automaticamente ou DGA.

- `value`: ratio dígitos/comprimento
- `normalized`: `normalize_counter(ratio, threshold=0.25)` — `None` se ratio = 0

**details:** `{ratio, analyzed}`

---

### `mixed_encoding`
**Peso:** 4.0 | **Severidade:** high

Detecta mistura de técnicas de encoding na URL. Ofuscação intencional combina múltiplos encodings para evadir filtros.

Técnicas detectadas:
- Percent encoding (`%xx`)
- Punycode (`xn--`)
- Caracteres Unicode (ord > 127)
- Double encoding (`%25`)

Scoring:
- Double encoding → `1.0`
- 2+ técnicas combinadas → `0.7`
- Menos de 2 técnicas → `None`

**details:** `{percent_encoding, unicode_chars, punycode, double_encoding}`

---

### `xss_risk`
**Peso:** 5.0 | **Severidade:** high

Detecta padrões de XSS na URL via regex.

Padrões detectados: `<script>`, `javascript:`, `onerror=`, `onload=`, `alert(`, `document.cookie`, `eval(`

- `value`: quantidade de indicadores encontrados
- `normalized`: binário — `1` se algum encontrado, `None` se nenhum

**details:** `{found_indicators}`

---

### `ip_in_url`
**Peso:** 3.0 | **Severidade:** medium

Verifica presença de endereços IP válidos na URL. IPs no lugar de hostname indicam infraestrutura descartável sem DNS estabelecido.

- `value`: `1.0` se IP válido encontrado
- `normalized`: `1.0` se IP válido; `minmax(matches, 0, 5)` para matches inválidos

**details:** `{match, risk}` ou `{matches}`

---

### `random_domain_risk`
**Peso:** 3.0 | **Severidade:** medium

Aplica entropia de Shannon no domínio registrado. Domínios DGA e gerados automaticamente têm alta entropia.

Curva de normalização:
- entropy ≤ 2.8 → `0.0`
- entropy ≥ 4.5 → `1.0`
- entre 2.8–4.5 → interpolação linear

**details:** `{domain, entropy, is_above_threshold}`

---

### `subdomain_count`
**Peso:** 2.0 | **Severidade:** low

Conta subdomínios na URL. Excesso de subdomínios é usado para ofuscação ou em phishing hospedado em plataformas cloud.

- `normalized`: `normalize_counter(count, threshold=3)` — `None` se count = 0

**details:** `{subdomain_count, subdomain}`

---

### `random_subdomain_risk`
**Peso:** 3.0 | **Severidade:** medium

Aplica entropia de Shannon em cada subdomínio individualmente. Subdomínios gerados dinamicamente têm alta entropia.

Scoring combina:
- Contagem de subdomínios suspeitos (`soft_score = count / (count + 0.5)`)
- Entropia média ponderada (`intensity = avg_entropy / 4.5`)
- Multiplicador 1.3× para subdomínios que parecem hashes

**details:** `{suspicious_subdomains, total_subdomains}`

---

### `random_path_risk`
**Peso:** 3.0 | **Severidade:** medium

Detecta segmentos do path com alta entropia ou padrão de hash. Caminhos aleatórios são comuns em URLs de campanhas de phishing descartáveis.

Segmento é suspeito se:
- `len >= 6` e `entropy > 3.2`, **ou**
- parece um hash (alphanum misto, ratio de caracteres únicos alto)

Scoring idêntico ao `random_subdomain_risk`.

**details:** `{suspicious_segments, total_segments, avg_entropy}`

---

### `query_no_value`
**Peso:** 1.5 | **Severidade:** low

Detecta parâmetros de query sem valor (ex: `?param=` ou `?param`). Parâmetros vazios são incomuns em URLs legítimas e podem indicar estrutura de payload incompleta.

- `normalized`: `min(count / 3, 1.0)` — `None` se nenhum

**details:** `{query, empty_params}`

---

### `query_contains_url`
**Peso:** 4.0 | **Severidade:** high

Detecta URLs embutidas em parâmetros de query. Indica open redirect, SSRF ou phishing encadeado.

- URL completa (`https://...`) → `normalized = 0.9`
- Path ou domínio parcial → `normalized = 0.5`
- Sem URL → `None`

**details:** `{param, original, decoded, is_full_url}`

---

### `shorteners_keyword_risk`
**Peso:** 3.0 | **Severidade:** medium

Compara o hostname com uma lista conhecida de encurtadores de URL usando similaridade Jaccard (threshold 0.75). URLs encurtadas ocultam o destino real.

**details:** `{suspicious_shorteners}`

---

### `length_domain`
**Peso:** 1.0 | **Severidade:** low

Penaliza domínios acima de 20 caracteres, com escala até 50. Domínios longos indicam ofuscação ou geração automática.

- `normalized`: `None` se `length < 20`; `minmax(length, 20, 50)` se acima

**details:** `{domain_length, threshold}`

---

### `length_path`
**Peso:** 2.5 | **Severidade:** medium

Detecta segmentos de path com mais de 25 caracteres. Segmentos muito longos indicam payloads, hashes ou tentativas de exploração.

**details:** `{big_paths, total_paths}`

---

### `path_depth_risk`
**Peso:** 1.5 | **Severidade:** low

Penaliza paths com profundidade acima de 5 níveis. Profundidade excessiva é usada para evadir scanners com limite de crawl.

- `normalized`: `minmax(depth, threshold, threshold * 2)` se `depth > 5`

**details:** `{depth, threshold}`

---

### `fragment_risk`
**Peso:** 1.0 | **Severidade:** low

Avalia entropia do fragmento (`#...`) da URL. Fragmentos com alta entropia podem conter dados ofuscados ou payloads de XSS via hash.

Scoring:
- `entropy_score = minmax(entropy, 2.5, 4.5)`
- `length_factor = 1.2` se `len > 30`
- `normalized = min(entropy_score * length_factor, 1.0)`

**details:** `{fragment_length, entropy, is_complex}`

---

### `typosquatting`
**Peso:** 3.5 | **Severidade:** high

Detecta similaridade entre o domínio e marcas conhecidas usando Levenshtein + índice por comprimento. Cobre técnicas como substituição de caracteres (`paypa1.com`), omissão, adição.

Wordlist carregada via `domain_generator` em startup. Se a wordlist não estiver disponível, retorna `None`.

**details:** `{matched_domain, distance, score}` (via `detect()`)

---

### `base64_segments`
**Peso:** 3.0 | **Severidade:** medium

Detecta segmentos codificados em Base64 ou tracking IDs em subdomínios, path, query e fragment.

Critérios: `len >= 12` e `is_base64()` ou `is_tracking_id()`

- `normalized`: `minmax(sus_count, 0, max_sus=3)`

**details:** `{base64_segments, total_segments}`

---

## Heurísticas HTML

> Todas as heurísticas HTML requerem `structure["html_parser"]` (árvore selectolax). Se `None`, retornam `normalized = None`.

### `form_action_check`
**Peso:** 3.0 | **Severidade:** high

Detecta formulários com `action` apontando para domínio externo. Indica coleta de credenciais com exfiltração direta.

- `normalized`: `1.0` se ação externa encontrada, `None` caso contrário

**details:** `{has_external_form_action, form_count, external_actions}`

---

### `favicon_check`
**Peso:** 2.0 | **Severidade:** low

Detecta favicon carregado de domínio externo (não do mesmo registrador). Phishing kits frequentemente clonam o favicon de marcas legítimas de um CDN externo.

Comparação usa `tldextract` para verificar se o domínio do favicon pertence ao mesmo registrador que o alvo.

- `normalized`: `1.0` se externo, `None` se ausente ou interno

**details:** `{favicon_found, favicon_url, favicon_domain}`

---

### `password_input_check`
**Peso:** 3.0 | **Severidade:** medium

Detecta `<input type="password">` na página. Isoladamente tem baixo sinal — o sistema de dependências amplifica o score quando combinado com outros indicadores.

- `normalized`: `1.0` se presente, `None` se ausente

**details:** `{has_password_input}`

---

### `missing_form_tag`
**Peso:** 2.0 | **Severidade:** medium

Detecta campos de credenciais (`email`, `password`, `text`) presentes sem nenhum `<form>`. Phishing moderno captura credenciais via JavaScript sem usar `<form>`.

Condição: `input_count > 0 AND form_count == 0`

**details:** `{input_count, form_count, suspicious}`

---

### `external_script`
**Peso:** 3.0 | **Severidade:** medium

Analisa scripts externos (`<script src="...">`) e classifica cada domínio de origem.

Pipeline de classificação por domínio:
1. Lista de domínios confiáveis (`TRUSTED_DOMAINS`) → categoria nomeada
2. ASN confiável (`TRUSTED_ASNS`: Cloudflare, AWS, Google, Azure, Akamai, Fastly, provedores BR) → `trusted_cdn`
3. Mesmo ASN da página → `same_infra`
4. Nenhum dos anteriores → `unknown` (suspeito)

Detecção de harvest: verifica scripts inline por padrões de `fetch`, `XMLHttpRequest`, `FormData`, `addEventListener('submit')` referenciando domínios externos.

Scoring:
- Harvest detectado → `1.0`
- Scripts suspeitos sem harvest → `0.5 + 0.5 * (sus / total)`
- Nenhum suspeito → `None`

**details:** `{has_suspicious_external_script, external_script_count, suspicious_script_count, unique_external_domains, domain_categories, suspicious_scripts, harvest_detected, harvest_domains}`

---

### `hidden_fields_check`
**Peso:** não registrado via `@register` no código atual — função definida mas sem decorator

Detecta `<input type="hidden">`. Campos ocultos em excesso (> 4) indicam formulários de coleta com dados rastreados.

- `normalized`: `None` se `count <= 4`; `(count - 4) / 6` se acima, cap em `1.0`

**details:** `{hidden_field_count, threshold, above_threshold}`

---

### `redirect_check`
**Peso:** 3.0 | **Severidade:** high

Detecta redirecionamentos JavaScript e meta refresh para domínios externos.

Fontes verificadas:
- `<meta http-equiv="refresh" content="...url=...">` — extrai domínio e compara com o alvo
- Scripts inline — regex sobre `window.location`, `window.location.href`, `location.replace()`

- `normalized`: `1.0` se redirect externo encontrado, `None` caso contrário

**details:** `{has_external_redirect, redirect_count, redirects[{type, target}]}`

---

### `script_integrity_absent`
**Peso:** 2.0 | **Severidade:** medium

Verifica scripts externos sem atributo `integrity` (SRI — Subresource Integrity). Scripts sem SRI podem ser substituídos por versões maliciosas sem detecção.

- `normalized`: `missing / total` para scripts externos; `None` se não há scripts externos

**details:** `{external_scripts, missing_integrity, samples}`

---

### `inline_data_uri`
**Peso:** 1.5 | **Severidade:** medium

Detecta atributos `src`, `data` ou `href` com `data:` URI em `img`, `script`, `iframe`, `embed`, `object`, `source`. Data URIs embutidos ocultam recursos externos e evitam requisições detectáveis.

- `normalized`: `min(count / 5, 1.0)` — `None` se nenhum

**details:** `{data_uri_count, samples[{tag, prefix}]}`

---

### `client_hints_collection`
**Peso:** 1.0 | **Severidade:** low

Detecta hints sensíveis no header `accept-ch` (Client Hints). Hints como `Device-Memory`, `arch`, `model`, `bitness`, `wow64` permitem fingerprinting avançado do dispositivo.

- `normalized`: `min(sensitive_count / 4, 1.0)` — `None` se nenhum sensível

**details:** `{hint_count, sensitive_count, sensitive_hints}`

---

### `image_src_check`
**Peso:** 1.5 | **Severidade:** low

Calcula a proporção de `<img>` com `src` apontando para domínio diferente do alvo. Alta proporção de imagens externas é comum em clones de sites legítimos.

- `value`: ratio externas/total
- `normalized`: `min(ratio, 1.0)` — `None` se ratio = 0

**details:** `{total_images, external_image_count, external_ratio, external_images}`

---

## Heurísticas SERVER

### `ssl_score`
**Peso:** 3.5 | **Severidade:** high

Avalia o certificado SSL/TLS com 10 sub-funções ponderadas, combinadas via sigmoid (k=5).

| Sub-função | Peso | O que avalia |
|---|---|---|
| `f_age(age_days)` | 1.5 | Idade desde emissão — certificados recentes têm risco máximo (decaimento exp., constante 120d) |
| `f_validity(days)` | 1.0 | Validade total: <30d→0.9, 30-90d→0.1, 91-398d→0.2, >398d→0.7 |
| `f_expiry(days)` | 1.5 | Dias até vencer — expiração iminente (decaimento exp., constante 7d) |
| `f_san(count)` | 0.5 | 0→0.8, 1-2→0.0, 3-10→0.1, >10→0.6 (CDN compartilhado) |
| `f_wildcard(san)` | 0.3 | Wildcard presente→0.2 |
| `f_issuer(name)` | 1.0 | CA confiável→0.0, Let's Encrypt→0.3, desconhecida→0.7 |
| `f_mismatch(bool)` | 2.0 | Hostname não bate com cert→1.0 |
| `f_self_signed(bool)` | 2.0 | Autoassinado→1.0 |
| `f_org(org)` | 0.5 | Sem campo Organization (DV cert)→0.3 |
| `f_sig_algorithm(alg)` | 1.0 | SHA256/384/512→0.0, SHA1→0.7, MD5→1.0, desconhecido→0.4 |

Sub-funções que retornam `None` (dados indisponíveis) são excluídas do cálculo sem penalização.

Casos especiais por erro de conexão:
- `connection_refused` → `normalized = 0.65`
- `timeout` → `normalized = 0.0`
- `invalid_cert` → `normalized = 0.9`

**details:** `{age_days, validity_days, days_until_expiry, san_count, issuer, hostname_valid, self_signed, organization, sig_algorithm}`

---

### `dns_score`
**Peso:** 3.5 | **Severidade:** medium

Combina 4 sub-scores DNS via sigmoid (k=5).

| Sub-score | Peso | O que avalia |
|---|---|---|
| `dns_ttl(ttl, has_mx)` | 0.8 | TTL<60→1.0, <300→0.5, ≤3600→0.0, >3600→0.1. MX atenua TTL baixo (×0.4); sem MX amplifica (×1.2) |
| `dns_a(ips, ttl)` | 0.9 | >8 IPs → risco logarítmico. TTL<120 + muitos IPs → multiplicador 1.3× (rotação suspeita) |
| `dns_spf(txt, has_mx)` | 0.7 | Sem SPF com MX→1.0; sem SPF sem MX→None; SPF ok→None |
| `dns_dkim(txt, has_mx)` | 0.6 | Sem DKIM com MX→0.1; sem DKIM sem MX→None |

DNS falho (sem resolução) → `normalized = 1.0` (máximo risco).

**details:** `{has_mx, ttl, ip_count, ips, scores{mx, ttl, a, spf, dkim}}`

---

### `domain_age`
**Peso:** 4.0 | **Severidade:** medium

Avalia a idade do domínio via RDAP (data de registro). Domínios recém-criados têm alta correlação com phishing e campanhas efêmeras.

Score via `domain_age_score(age_days)` (decaimento exponencial). Sem dados RDAP → `normalized = None`.

**details:** `{creation_date, age_days}`

---

### `nameserver_diversity`
**Peso:** 3.0 | **Severidade:** medium

Avalia diversidade de nameservers via RDAP. Nameserver único ou com todos ns no mesmo domínio indica infraestrutura mínima descartável.

Scoring:
- 1 nameserver → `0.9`
- 2 nameservers diferentes → `0.6`
- diversity ratio > 0.8 → `0.5`
- diversidade normal → `0.0`

**details:** `{unique_ns_domains, nameserver_count, diversity_ratio}`

---

### `rdap_metadata_incompleteness`
**Peso:** 3.5 | **Severidade:** low

Verifica campos ausentes no RDAP: `entities`, `nameservers`, `events`. Cada campo ausente contribui com `1/3` do score.

- `normalized`: `missing / 3`

**details:** `{missing_fields}`

---

### `safe_browsing`
**Peso:** 4.0 | **Severidade:** high

Consulta resultado da Google Safe Browsing API (dado injetado no `structure["safe_browsing"]` pelo pipeline de coleta).

- `normalized`: `1.0` se flagged, `None` se não flagged, `None` se dado indisponível

**details:** `{flagged, threat_types}`

---

## Sistema de Dependências

Após a execução de todas as heurísticas, o pipeline aplica ajustes de peso baseados nas relações entre regras definidas em `DEPENDENCIES`.

### Ações disponíveis

| Ação | Efeito |
|---|---|
| `reduce` | Multiplica o `normalized` da regra alvo pelo `factor` (< 1.0) — atenua o score |
| `increase` | Multiplica o `normalized` da regra alvo pelo `factor` (> 1.0) — amplifica o score, cap em 1.0 |
| `skip` | Define `normalized = None` — remove a regra do cálculo de score |

### Operadores de condição

| Operador | Descrição |
|---|---|
| `<` | `depends_on.normalized < val` |
| `>` | `depends_on.normalized > val` |
| `>=` | `depends_on.normalized >= val` |
| `is_none` | `depends_on.normalized is None` |

### Resolução de conflitos

Quando `reduce` e `increase` disparam simultaneamente para a mesma regra alvo, `reduce` vence.

### Exemplos de dependências notáveis

**`ssl_score` + `domain_age` baixo → redução:**
```
ssl_score depende de domain_age < 0.1
→ reduce × 0.1
→ "domínio muito antigo com SSL suspeito — provável renovação ou CDN"
```

**`typosquatting` + `password_input_check` → amplificação:**
```
typosquatting depende de password_input_check >= 0.5
→ increase × 1.6
→ "credential harvesting em domínio similar confirmado"
```

**`form_action_check` + `password_input_check` → amplificação:**
```
form_action_check depende de password_input_check >= 0.5
→ increase × 1.5
→ "credential harvesting confirmado"
```

**`random_subdomain_risk` + `subdomain_count` ausente → skip:**
```
random_subdomain_risk depende de subdomain_count is_none
→ skip
→ "sem subdomínios detectados"
```

---

## Mapa de Dependências

Resumo das relações entre regras (A → B significa "A tem dependência de B"):

```
ssl_score         → domain_age, dns_score, random_domain_risk, ip_in_url
domain_age        → dns_score, ssl_score, random_domain_risk, rdap_metadata_incompleteness
dns_score         → domain_age, ssl_score, random_domain_risk, ip_in_url, random_path_risk
rdap_metadata     → domain_age, ssl_score, dns_score, nameserver_diversity
nameserver_div    → domain_age, ssl_score, random_domain_risk, rdap_metadata
hyphen_risk       → domain_age, ssl_score, random_domain_risk, num_ratio_risk
at_risk           → domain_age, ssl_score, random_domain_risk, ip_in_url
equal_risk        → domain_age, ssl_score, mixed_encoding, xss_risk, query_contains_url
num_ratio_risk    → domain_age, ssl_score, random_domain_risk, hyphen_risk
mixed_encoding    → domain_age, ssl_score, xss_risk, base64_segment, at_risk
xss_risk          → domain_age, ssl_score, mixed_encoding, query_contains_url, equal_risk
ip_in_url         → domain_age, ssl_score, password_input_check, random_path_risk
subdomain_count   → domain_age, ssl_score, random_domain_risk, random_subdomain_risk, dns_score
random_domain     → domain_age, ssl_score, dns_score
random_subdomain  → subdomain_count, domain_age, ssl_score, dns_score, random_domain_risk, password_input_check, random_path_risk
random_path       → domain_age, ssl_score, random_domain_risk, password_input_check
query_no_value    → domain_age, ssl_score, query_contains_url, mixed_encoding
query_contains_url→ domain_age, ssl_score, mixed_encoding, at_risk
base64_segment    → domain_age, ssl_score, mixed_encoding, path_depth_risk
path_depth_risk   → domain_age, ssl_score, random_domain_risk, base64_segment, random_path_risk
fragment_risk     → domain_age, ssl_score, xss_risk, mixed_encoding, random_path_risk
external_script   → domain_age, ssl_score, random_domain_risk, form_action_check, password_input_check
favicon_check     → domain_age, ssl_score, random_domain_risk, password_input_check, form_action_check
image_src_check   → domain_age, ssl_score, random_domain_risk, form_action_check, password_input_check
redirect_check    → domain_age, ssl_score, random_domain_risk, password_input_check, random_subdomain_risk
hidden_fields     → domain_age, ssl_score, random_domain_risk, form_action_check, password_input_check
password_input    → domain_age, ssl_score, random_domain_risk, form_action_check, random_subdomain_risk, ip_in_url
form_action       → domain_age, ssl_score, random_domain_risk, password_input_check, random_subdomain_risk, ip_in_url
safe_browsing     → domain_age, ssl_score, random_domain_risk, password_input_check, dns_score
client_hints      → domain_age, ssl_score, password_input_check, safe_browsing
inline_data_uri   → domain_age, ssl_score, random_domain_risk, password_input_check, safe_browsing, form_action_check
missing_form_tag  → domain_age, ssl_score, random_domain_risk, safe_browsing, random_subdomain_risk
script_integrity  → domain_age, ssl_score, random_domain_risk, safe_browsing, password_input_check, form_action_check
typosquatting     → domain_age, ssl_score, dns_score, random_domain_risk, password_input_check, form_action_check, safe_browsing, favicon_check, rdap_metadata
```

---

## Matemática do Score Final

1. Cada heurística produz `normalized ∈ [0.0, 1.0]` ou `None`
2. Dependências ajustam os `normalized` via `reduce`/`increase`/`skip`
3. Regras com `normalized = None` são excluídas
4. Score bruto = média ponderada dos `normalized` restantes pelos `weight`
5. Score final = `sigmoid(score_bruto, k=5)` → mapeado para `[0, 100]`

---

## Limitações Conhecidas

**SPAs e React:** O HTML coletado é o HTML server-side. Sites que renderizam conteúdo via JavaScript retornam HTML vazio ou mínimo. Todas as heurísticas HTML retornam `None` nesses casos — o score fica dependente exclusivamente das heurísticas de URL e SERVER.

**CDNs e load balancers:** `nameserver_diversity` pode produzir falso positivo para domínios que usam Google Cloud DNS, Cloudflare, ou qualquer provedor DNS centralizado. As dependências atenuam esse sinal quando `domain_age` é baixo.

**Cloudflare:** Diversidade de nameservers de CDN ativa a regra `nameserver_diversity` com score alto, mas as dependências de `domain_age` e `ssl_score` reduzem o impacto em domínios estabelecidos.