# ScamLens — Modular System for Scam Detection

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

ScamLens é uma API de backend modular para análise de URLs e QR codes, com detecção automatizada de indicadores de phishing e golpes baseada em heurísticas e machine learning.

---

## Índice

- [Visão geral](#visão-geral)
- [Diferenciais](#diferenciais)
- [Arquitetura](#arquitetura)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Endpoints principais](#endpoints-principais)
- [Autenticação](#autenticação)
- [Open source](#open-source)
- [Contribuição](#contribuição)

---

## Visão geral

ScamLens analisa URLs e QR codes em busca de padrões maliciosos. O sistema combina um pipeline de coleta de dados em múltiplas camadas (DNS, RDAP, SSL, Safe Browsing, HTTP) com heurísticas declarativas e um modelo de machine learning para produzir um score de risco final.

É a API que alimenta o site [phishware.com](https://phishware.com/), uma plataforma de detecção de scams.

---

## Diferenciais

- **Pipeline estruturado de análise de URL** — `validate_url → collect → target_structure → context_apply → execute → score → response_builder`
- **Análise de QR code** — decodificação via `pyzbar` com fallback para `zxingcpp`, cobrindo payloads de URL.
- **Sistema de autenticação JWT** — tokens de acesso + refresh tokens com rotação, verificação de e-mail via Resend, e cookies `httpOnly`
- **Heurísticas extensíveis** — registradas via decorador `@register`, organizadas por categoria (URL, HTML, servidor)
- **Cache eficiente** — chaves SHA-256 por URL com SQLite em modo WAL para alta concorrência
- **Rate limiting por plano** — usuários anônimos (3 scans/dia por IP), standard, go_pro e plus_premium com cotas configuráveis

---

## Arquitetura

```
scamLens/
├── api/                  # Roteadores FastAPI
├── modules/
│   ├── scurl/            # Módulo de análise de URL
│   └── scqr/             # Módulo de análise de QR code
├── providers/            # Camadas de coleta: http, dns, rdap, ssl, safebrowsing, database
├── math_functions/       # Scoring: weighted_average, sigmoid, dependências multiplicativas
└── scamLens/             # Pacote wrapper (config.toml, entry points)
```

Para detalhes completos, veja [Arquitetura](./docs/architecture.md).

---

## Pré-requisitos

- Python 3.10+
- SQLite 3.x
- Nginx (produção)

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/JuaanReis/ScamLens
cd ScamLens

# Configure as variáveis de ambiente
cp .env.example .env
# Edite .env com suas chaves (JWT_SECRET, RESEND_API_KEY, SAFE_BROWSING_KEY, etc.)

# Inicie o servidor
scamlens-api

# Ou
py -m server.api
```

A API estará disponível em `http://localhost:8000`.

---

## Uso

### Analisar uma URL

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://exemplo-suspeito.com"}'
```

**Resposta:**

```json
{
  "url": "https://exemplo-suspeito.com",
  "score": 0.87,
  "risk": "high",
  "flags": [
    "domain_age_low",
    "ssl_invalid",
    "suspicious_tld",
    "typosquatting_detected"
  ],
  "details": {
    "dns": { "nameserver_diversity": 1 },
    "ssl": { "valid": false },
    "http": { "redirects": 3, "status_code": 200 }
  }
}
```

---

## Endpoints principais

| Método | Endpoint | Descrição | Auth |
|--------|----------|-----------|------|
| `POST` | `/analyze` | Análise de URL | Opcional |
| `POST` | `/analyze/qr` | Análise de QR code (upload de imagem) | Opcional |
| `POST` | `/auth/register` | Cadastro de usuário | — |
| `POST` | `/auth/login` | Login (retorna cookies `httpOnly`) | — |
| `POST` | `/auth/refresh` | Renovação de access token | Cookie |
| `POST` | `/auth/logout` | Logout | Cookie |
| `GET`  | `/scans/history` | Histórico de scans do usuário | Obrigatório |

---

## Autenticação

ScamLens usa JWT com dois tokens:

- **Access token** — curta duração, enviado via cookie `httpOnly`
- **Refresh token** — longa duração, com rotação a cada uso

Usuários não autenticados têm acesso limitado a **3 análises por dia** (rastreadas por IP). Planos pagos desbloqueiam cotas maiores e acesso a endpoints protegidos.

Fluxo de registro:

1. `POST /auth/register` com e-mail e senha
2. Verificação de e-mail via link enviado pelo Resend
3. `POST /auth/login` para obter os tokens

---

## Open source

ScamLens é distribuído sob a licença [MIT](LICENSE.md). Uso livre para fins pessoais, acadêmicos e comerciais.

---

## Contribuição

Contribuições são bem-vindas. Para contribuir:

1. Fork o repositório
2. Crie uma branch para sua feature: `git checkout -b feature/minha-feature`
3. Commit suas mudanças: `git commit -m 'feat: adiciona minha feature'`
4. Abra um Pull Request descrevendo o que foi feito e por quê

Para bugs ou sugestões, abra uma [issue](https://github.com/JuaanReis/ScamLens/issues).