# ScamLens

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.139.0-009688?logo=fastapi)
![Version](https://img.shields.io/badge/version-1.5.0-informational)

API de backend modular para análise de URLs e QR codes, com detecção de indicadores de phishing baseada em heurísticas declarativas e coleta multicamada de dados.

---

## Índice

- [Visão geral](#visão-geral)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Endpoints](#endpoints)
- [Autenticação](#autenticação)
- [Open source](#open-source)
- [Contribuição](#contribuição)

---

## Visão geral

ScamLens analisa URLs e QR codes em busca de padrões maliciosos. O sistema combina um pipeline de coleta em múltiplas camadas (DNS, RDAP, SSL, Safe Browsing, HTTP/HTML) com heurísticas declarativas registradas via `@register` para produzir um score de risco.

Pipeline de análise de URL:

```
validate_url → collect → target_structure → context_apply → execute → score → response_builder
```

O motor de QR (`scqr`) decodifica a imagem, classifica o tipo de payload e, quando é uma URL, passa pelo mesmo pipeline acima. Outros tipos de payload (Pix, Wi-Fi, vCard, e-mail, etc.) são detectados mas ainda não analisados nesta versão.

---

## Pré-requisitos

- Python 3.10+
- SQLite 3.x (incluso na stdlib)
- Nginx (apenas para deploy em produção)

---

## Instalação

```bash
git clone https://github.com/JuaanReis/scamlens.git
cd scamlens

python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

pip install -e .
```

Configure as variáveis de ambiente (crie um `.env` na raiz):

```bash
EMAIL_ADMIN=admin@exemplo.com
PASSWORD_ADMIN=senha_forte
JWT_SECRET=string_longa_e_aleatoria
GOOGLE_SAFE_BROWSING_KEY=sua_chave

# Opcional — default é "production" (desabilita /docs e /redoc)
SCAMLENS_ENV=development

# Opcional — default inferido a partir do repo
SCAMLENS_DB_PATH=./providers/storage/db/scamlens.db
```

Suba o servidor:

```bash
scamlens-api
```

A API estará disponível em `http://localhost:8000`. Na primeira execução, a conta admin é criada automaticamente a partir de `EMAIL_ADMIN`/`PASSWORD_ADMIN`.

Com `SCAMLENS_ENV=development`, a documentação interativa fica disponível em `/docs` e `/redoc`.

---

## Uso

### Analisar uma URL

```bash
curl -X POST http://localhost:8000/api/scurl/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://exemplo-suspeito.com", "use_cache": false}'
```

Resposta (`200`):

```json
{
  "scan": {
    "status": "ok",
    "engine": { "name": "scurl", "version": "..." },
    "meta": {
      "scan_id": "abc123",
      "scan_time_s": 1.42,
      "url_hash": "sha256...",
      "url": "https://exemplo-suspeito.com",
      "threads": 1,
      "timestamp": "2026-07-28T00:00:00Z"
    },
    "result": {
      "score": 0.83,
      "risk_level": "high",
      "verdict": "likely_phishing"
    },
    "stats": {
      "rules_total": 20,
      "rules_triggered": 7,
      "trigger_rate": 0.35
    },
    "heuristics": [...],
    "insight": ["Domain registered less than 7 days ago", "Invalid SSL certificate"]
  },
  "target": {
    "identity": { "hostname": "exemplo-suspeito.com", "is_idn": false, ... },
    "network": { "ipv4": [...], "asn": {...}, "geo": {...}, ... },
    "tls": { "enabled": true, "valid_from": "...", "self_signed": true, ... },
    "dns": { "a": [...], "ns": [...], "spf": false, "dmarc": false, ... },
    "http": { "status_code": 200, "redirects": 2, "security_headers": {...}, ... },
    "content": { "title": "...", "forms": {"count": 1, "password_fields": 1}, ... },
    "domain": { "registrar": "...", "age_days": 3, ... }
  }
}
```

Sem autenticação, o endpoint aceita até **3 análises por dia** por IP. Requisições além do limite retornam `401`.

### Analisar um QR code

```bash
curl -X POST http://localhost:8000/api/scurl/qr/analyze/qr \
  -F "file=@qrcode.png"
```

Aceita JPEG, PNG, WebP, GIF (validado por magic bytes, não por `Content-Type`). O payload extraído do QR deve ser uma URL — outros tipos retornam `400` com `error.type: "unsupported_qr_type"`.

### CLI

Além da API, o motor de URL pode ser usado diretamente:

```bash
scurl https://exemplo-suspeito.com
scurl https://exemplo-suspeito.com -v              # verbose
scurl https://exemplo-suspeito.com -o resultado.json
scurl https://exemplo-suspeito.com -t 4 -T 10      # 4 threads, timeout 10s
scurl https://exemplo-suspeito.com -c              # usa cache local
```

---

## Endpoints

| Método | Endpoint | Auth | Descrição |
|--------|----------|------|-----------|
| `POST` | `/api/scurl/analyze/url` | Opcional | Analisa uma URL |
| `POST` | `/api/scurl/qr/analyze/qr` | Opcional | Analisa uma imagem com QR code |
| `GET` | `/api/scurl/scans` | — | Lista histórico público de scans |
| `GET` | `/api/scurl/scans/{id}` | — | Detalhe de um scan |
| `POST` | `/api/auth/register` | — | Cadastro de usuário |
| `POST` | `/api/auth/login` | — | Login (seta cookies httpOnly) |
| `POST` | `/api/auth/refresh` | Cookie | Renova o access token |
| `POST` | `/api/auth/logout` | Cookie | Revoga tokens e limpa cookies |
| `GET` | `/api/user/me` | Cookie | Perfil e atividade do usuário |
| `POST` | `/api/user/avatar` | Cookie | Upload de avatar (JPEG/PNG/WebP/GIF, 2MB) |
| `GET` | `/api/admin/*` | Admin | Métricas, usuários, scans, logs |
| `GET` | `/health` | — | Liveness probe (verifica banco) |

Para a referência completa, veja [docs/usage.md](./docs/USAGE.md).

---

## Autenticação

ScamLens usa dois JWTs assinados com `HS256`, transmitidos como cookies `httpOnly`. Rotas protegidas também aceitam `Authorization: Bearer <access_token>` como alternativa ao cookie.

| Token | Duração |
|-------|---------|
| Access token | 30 minutos |
| Refresh token | 1 dia (`remember: false`) ou 30 dias (`remember: true`) |

Revogação por blocklist de `jti` — logout invalida ambos os tokens imediatamente, independente da expiração.

Cotas de análise por dia:

| Usuário | Limite |
|---------|--------|
| Anônimo (por IP) | 3 |
| `standard` | 5 |
| `go_pro` | 25 |
| `plus_premium` | ilimitado |

---

## Open source

ScamLens é distribuído sob a licença [MIT](LICENSE.md). Uso livre para fins pessoais, acadêmicos e comerciais.

---

## Contribuição

Contribuições são bem-vindas. Para contribuir:

1. Fork o repositório
2. Crie uma branch: `git checkout -b feat/minha-feature`
3. Commit: `git commit -m 'feat: descrição clara do que foi feito'`
4. Abra um Pull Request

Para bugs ou sugestões, abra uma [issue](https://github.com/JuaanReis/ScamLens/issues).