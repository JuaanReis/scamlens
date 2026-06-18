# scurl CLI Reference

## Uso

```
scurl [TARGET] [OPTIONS]
```

A URL alvo pode ser passada como argumento posicional ou via flag `-u`. Não é possível usar os dois ao mesmo tempo.

---

## Argumentos e Flags

| Flag | Alias | Tipo | Default | Descrição |
|---|---|---|---|---|
| `target` | — | `str` | — | URL alvo (posicional) |
| `--url` | `-u` | `str` | — | URL alvo (nomeada) |
| `--verbose` | `-v` | `bool` | `false` | Ativa saída verbosa |
| `--threads` | `-t` | `int` | `1` | Número de threads do engine |
| `--output` | `-o` | `str` | — | Caminho do arquivo de saída JSON. Use `-` para stdout |
| `--timeout` | `-T` | `float` | `5` | Timeout de rede em segundos |
| `-k` | — | `int` | `5` | Parâmetro k do pipeline de scoring |
| `--retries` | `-r` | `int` | `3` | Tentativas de reconexão em falha de rede |
| `--cache` | `-c` | `bool` | `false` | Ativa leitura/escrita de cache no SQLite |
| `--disable-color` | `-dc` | `bool` | `false` | Desativa saída colorida (colorama) |

---

## Exemplos

```bash
# Scan básico
scurl https://example.com

# Com flag -u
scurl -u https://example.com

# Mais threads, timeout maior
scurl https://example.com -t 4 -T 10

# Salvar resultado em arquivo JSON
scurl https://example.com -o resultado.json

# Saída JSON no stdout (para piping)
scurl https://example.com -o -

# Com cache SQLite ativo
scurl https://example.com -c

# Sem cores (útil para logs e CI)
scurl https://example.com -dc
```

---

## Saída

Quando executado normalmente (sem `-o -`), o CLI imprime as seções abaixo em sequência.

### Ordem de seções

```
TARGET
NETWORK
REDIRECT CHAIN       ← só aparece se houver redirecionamentos
INFRASTRUCTURE
SECURITY POSTURE
TLS ANALYSIS
DNS INTELLIGENCE
FINGERPRINT
ENGINE
HEURISTICS
FINDINGS
INSIGHTS
RISK SCORE
ASSESSMENT
─── footer
```

---

### TARGET

Informações básicas sobre a URL analisada.

| Campo | Descrição |
|---|---|
| `URL` | URL original fornecida |
| `Host` | Hostname extraído |
| `Registered` | Domínio registrado (ex: `youtube.com`) |
| `Scheme` | `HTTP` ou `HTTPS` |
| `Subdomains` | Quantidade de subdomínios |
| `HTTPS` | `ENABLED` / `DISABLED` |

---

### NETWORK

Dados da resposta HTTP.

| Campo | Descrição |
|---|---|
| `Status` | Código HTTP da resposta final |
| `Response Time` | Tempo de resposta em segundos |
| `Payload Size` | Tamanho do body em KB |
| `Compression` | Algoritmo de compressão (`brotli`, `gzip`, `none`, etc.) |
| `Redirects` | Número de redirecionamentos seguidos |
| `HTTP3` | `ENABLED` se `h3=` presente no header `alt-svc` |

---

### REDIRECT CHAIN

Exibida somente quando `redirects > 0`. Mostra cada passo da cadeia com status HTTP e URL de destino.

```
[301] https://example.com
  └─▶ https://www.example.com
[200] https://www.example.com
```

---

### INFRASTRUCTURE

Inferências sobre a infraestrutura do alvo.

| Campo | Descrição |
|---|---|
| `Server` | Valor do header `Server` |
| `providers` | `Google` se server header contém `ESF`, `GSE`, `GFE` ou `GOOGLE`; caso contrário `Unknown` |
| `CDN` | `Likely` se Google ou Cloudflare detectado no server header |
| `TLS` | Sempre `ENABLED` nesta seção |
| `Edge Network` | `DETECTED` se infraestrutura Google ou HTTP/3 presente |

---

### SECURITY POSTURE

Análise dos headers de segurança HTTP.

| Campo | Fonte | Descrição |
|---|---|---|
| `HSTS` | `strict-transport-security` | `ENABLED` se header presente |
| `CSP` | `content-security-policy` | `ENABLED` se header presente |
| `Trusted Types` | `content-security-policy` | `ENABLED` se `require-trusted-types-for` presente na CSP |
| `X-Frame` | `x-frame-options` | Valor bruto do header (`SAMEORIGIN`, `DENY`, `DISABLED`) |
| `X-Content-Type` | `x-content-type-options` | Valor bruto do header |
| `XSS Protection` | `x-xss-protection` | `ENABLED` se header presente e diferente de `0` |

---

### TLS ANALYSIS

Dados extraídos dos `details` da regra `ssl_score`.

| Campo | Descrição |
|---|---|
| `Issuer` | Nome curto da CA emissora |
| `Self Signed` | `YES` / `NO` |
| `Hostname Match` | `YES` se o hostname bate com o CN/SAN do certificado |
| `SAN Count` | Número de Subject Alternative Names |
| `Cert Age` | Idade do certificado em dias desde `valid_from` |
| `Validity` | Validade total do certificado em dias |

---

### DNS INTELLIGENCE

| Campo | Descrição |
|---|---|
| `MX Record` | `PRESENT` / `ABSENT` |
| `TTL` | TTL do registro A em segundos |
| `IPs` | Número de endereços IPv4 resolvidos |
| `Load Balanced` | `LIKELY` se mais de 1 IP ou TTL < 120s |

---

### FINGERPRINT

Metadados de identificação do scan.

| Campo | Descrição |
|---|---|
| `Scan ID` | Primeiros 14 caracteres do `scan_id` formatados como `xxxxxxxx-xxxxxx` |
| `URL SHA256` | Primeiros 18 caracteres do hash SHA-256 da URL + `...` |
| `Threads` | Número de threads usado no scan |
| `Timestamp` | Data e hora do scan em UTC (`YYYY-MM-DD HH:MM:SS UTC`) |

---

### ENGINE

Estatísticas de execução do pipeline de regras.

| Campo | Descrição |
|---|---|
| `Processors` | Número de threads |
| `Rules Loaded` | Total de regras registradas |
| `Triggered` | Regras que produziram resultado (não `None`) |
| `Suppressed` | `Rules Loaded - Triggered` — regras que retornaram `None` |
| `Trigger Rate` | `triggered / total` em percentual |

---

### HEURISTICS

Tabela com todas as regras que triggeram, formatada dinamicamente com colunas ajustadas ao conteúdo.

```
MODULE    RULE                   VALUE  WEIGHT  CONTRIB
SERVER    ssl_score               0.00     3.5      0.0
SERVER    dns_score               0.01     3.5      0.0
HTML      client_hints_collection 0.00     1.0      0.0
```

| Coluna | Descrição |
|---|---|
| `MODULE` | Categoria da regra (`SERVER`, `HTML`, `URL`, `DOMAIN`) |
| `RULE` | Nome da regra |
| `VALUE` | Score bruto (0.00–1.00) |
| `WEIGHT` | Peso da regra no pipeline |
| `CONTRIB` | Contribuição ponderada no score final |

Regras que retornam `None` (sinal não aplicável) não aparecem.

---

### FINDINGS

Razões geradas pelas regras, separadas em dois grupos:

- `[+]` (verde) — indicadores positivos / normais
- `[!]` (amarelo) — indicadores que contêm palavras-chave de alerta: `suspeito`, `antigo`, `renovação`, `não convencional`

Seção omitida se não houver findings.

---

### INSIGHTS

Observações derivadas das inferências + campo `insight` do engine.

Exemplos de insights derivados automaticamente:

- `Target pertence provavelmente à infraestrutura Google` — quando server header indica Google
- `HTTP/3 detectado via alt-svc` — quando `h3=` presente no `alt-svc`
- `Política Trusted Types presente` — quando CSP contém `require-trusted-types-for`
- `Headers indicam hardening de navegador` — quando `permissions-policy` presente

Seção omitida se não houver insights.

---

### RISK SCORE

Score final do engine com barra visual.

```
7.80 / 100.00
[█░░░░░░░░░] VERY LOW
```

| Score | Cor | Label |
|---|---|---|
| 0–39 | Verde | `SAFE` |
| 40–69 | Amarelo | `SUSPICIOUS` |
| 70–100 | Vermelho | `DANGEROUS` |

A barra tem 10 segmentos. Cada segmento representa 10 pontos.

---

### ASSESSMENT

Texto descritivo em português baseado no `risk_level`.

| `risk_level` | Mensagem |
|---|---|
| `very low` | Infraestrutura corporativa estabelecida. Nenhum indicador forte de phishing detectado. |
| `low` | Baixo risco geral. Alguns indicadores merecem atenção mas não são conclusivos. |
| `medium` | Indicadores moderados de risco. Recomenda-se cautela e verificação adicional. |
| `high` | Múltiplos indicadores de risco. Evite interagir sem verificação prévia. |
| `very high` | Fortes indicadores de atividade maliciosa. Interação não recomendada. |

---

### Footer

```
Scurl concluído em 0.91s
────────────────────────────────────────
```

Se `--cache` foi usado, o tempo exibido é calculado de `time()` desde o início do `main()`. Caso contrário, usa `scan_time_s` retornado pelo engine.

---

## Saída JSON (`-o`)

Quando `-o <arquivo>` ou `-o -` é passado, o resultado é serializado em JSON com indentação de 2 espaços e encoding UTF-8.

O JSON tem o campo `url` injetado no topo do objeto `scan`:

```json
{
  "url": "https://example.com",
  "status": "ok",
  "engine": { ... },
  "meta": { ... },
  "result": { ... },
  ...
}
```

Com `-o -` o JSON é escrito em stdout e pode ser redirecionado:

```bash
scurl https://example.com -o - | jq .result
```

---

## Cache (`--cache` / `-c`)

Quando ativo:

1. Antes do scan, verifica se há resultado para a URL no SQLite (por `url_hash`)
2. Se encontrado, retorna o resultado cacheado sem refazer o scan
3. Se não encontrado, executa o scan e persiste o resultado

O banco é inicializado em `~/.scurl/scurl.db` por padrão. O path pode ser sobrescrito via variável de ambiente:

```bash
SCURL_DB_PATH=/caminho/custom.db scurl https://example.com -c
```

---

## Cores

A saída colorida usa `colorama`. Desativada automaticamente se `config["output"]["colors"]` for `false`, ou manualmente com `--disable-color` / `-dc`.

| Cor | Uso |
|---|---|
| Ciano brilhante | Títulos de seção |
| Branco | Chaves dos campos |
| Amarelo | Valores dos campos |
| Verde | `ENABLED`, `YES`, `PRESENT`, score baixo, findings positivos |
| Amarelo | Score médio, findings de alerta |
| Vermelho brilhante | `NO`, score alto, findings de perigo |
| Dim | `DISABLED`, `ABSENT`, `UNLIKELY` |