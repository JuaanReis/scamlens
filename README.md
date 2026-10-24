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
```

Suba o servidor:

```bash
python -m api.server
```

Execute esse comando na raiz do projeto. Se preferir `scamlens-api`, instale esta cópia no ambiente virtual com `python -m pip install -e .`; o comando global pode apontar para outra instalação.

A API estará disponível em `http://localhost:5300`. Na primeira execução, a conta admin é criada automaticamente a partir de `EMAIL_ADMIN`/`PASSWORD_ADMIN`.

Com `SCAMLENS_ENV=development`, a documentação interativa fica disponível em `/docs` e `/redoc`.

Os logs usam uma pasta por execução e uma subpasta `process_<PID>` para cada processo, contendo um arquivo ativo de eventos e um `host_info.txt` com os dados da inicialização. A gravação ocorre em lotes, com rotação e retenção. Níveis por categoria, filtros de requisições e limites do SQLite são configurados nas seções `[logs]` do `scamLens/config.toml`.

---

## Uso

### Analisar uma URL

```bash
curl -X POST http://localhost:5300/api/scurl/analyze/url \
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
curl -X POST http://localhost:5300/api/scurl/qr/analyze/qr \
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

Para analisar um Pix copia e cola localmente:

```bash
scpix --payload '000201...6304ABCD' --json
scpix --file cobranca.txt --expected-name 'LOJA EXEMPLO' --expected-amount 35.90
```

O SCPIX avalia anomalias técnicas e contextuais do BR Code. Cobranças dinâmicas não são consultadas automaticamente. Veja [plugins/scpix/README.md](plugins/scpix/README.md) para formatos de entrada, heurísticas e limites.

---

## Endpoints

| Método | Endpoint | Auth | Descrição |
|--------|----------|------|-----------|
| `POST` | `/api/scurl/analyze/url` | Opcional | Analisa uma URL |
| `POST` | `/api/scurl/qr/analyze/qr` | Opcional | Analisa uma imagem com QR code |
| `POST` | `/api/scfs/analyze/file` | Opcional | Analisa um executável ou script por upload |
| `POST` | `/api/scpix/analyze/pix` | Opcional | Analisa um Pix copia e cola enviado como JSON (`payload` e `expected` opcional) |
| `GET` | `/api/chat/messages` | Obrigatória | Lista mensagens do chat com paginação |
| `POST` | `/api/chat/messages` | Obrigatória | Persiste e transmite uma mensagem |
| `WebSocket` | `/api/chat/ws` | Obrigatória | Recebe mensagens em tempo real |
| `GET` | `/api/scurl/scans` | — | Lista histórico público de scans |
| `GET` | `/api/scurl/scans/{id}` | — | Detalhe de um scan |
| `GET` | `/api/scfs/scans` | Obrigatória | Histórico de arquivos do usuário; admin pode ver todos |
| `GET` | `/api/scfs/scans/{scan_id}` | Obrigatória | Resultado salvo de análise de arquivo |
| `GET` | `/api/scpix/scans` | Obrigatória | Histórico Pix do usuário; admin pode ver todos |
| `GET` | `/api/scpix/scans/{scan_id}` | Obrigatória | Resultado salvo de análise Pix |
| `GET` | `/api/user/scans` | Obrigatória | Meu histórico de URL/QR, arquivos e Pix, com filtro `module` |
| `POST` | `/api/auth/register` | — | Cadastro de usuário |
| `POST` | `/api/auth/login` | — | Login (seta cookies httpOnly) |
| `POST` | `/api/auth/refresh` | Cookie | Renova o access token |
| `POST` | `/api/auth/logout` | Cookie | Revoga tokens e limpa cookies |
| `GET` | `/api/user/me` | Cookie | Perfil e atividade do usuário |
| `POST` | `/api/user/avatar` | Cookie | Upload de avatar (JPEG/PNG/WebP/GIF, 2MB) |
| `GET` | `/api/admin/*` | Admin | Métricas, usuários, scans, logs |
| `GET` | `/health` | — | Liveness probe (verifica banco) |

Para a referência completa, veja [docs/usage.md](./docs/USAGE.md).

Análises de arquivos e Pix concluídas pela API são salvas automaticamente em `module_scans`, incluindo resultados parciais. Repetições do mesmo alvo geram registros separados. O banco guarda o resultado estruturado; arquivos enviados, payload Pix bruto, chave completa e token de cobrança dinâmica não são persistidos. Resultados anônimos ficam disponíveis apenas para administradores. Os motores e CLIs de SCFS/SCPIX continuam sem persistência automática.

`GET /api/admin/scans?module=scpix` reúne os módulos; `module` e `user_id` são filtros opcionais. `GET /api/admin/request-logs?module=scpix` permite filtrar por `module`, `scan_id`, `user_id` e `status_code`; QR aparece como `scqr` nos logs e compartilha o histórico de resultados de URL (`scurl`). As métricas de administração e `/api/user/me` incluem arquivos e Pix. O SCIMG ainda não produz análises e não participa desse histórico. Veja [docs/USAGE.md](docs/USAGE.md).

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

ScamLens é distribuído sob a licença [MIT](LICENSE). Uso livre para fins pessoais, acadêmicos e comerciais.

---

## Contribuição

Contribuições são bem-vindas. Para contribuir:

1. Fork o repositório
2. Crie uma branch: `git checkout -b feat/minha-feature`
3. Commit: `git commit -m 'feat: descrição clara do que foi feito'`
4. Abra um Pull Request

Para bugs ou sugestões, abra uma [issue](https://github.com/JuaanReis/ScamLens/issues).

## Garantias de execução

O limite por minuto é aplicado por IP, rota e método, por processo da API. A cota diária é reservada atomicamente no SQLite antes da análise e devolvida em erros normais. Cancelar a requisição depois de submeter o motor mantém a cobrança e a vaga ocupada até ele terminar; isso evita análises gratuitas e trabalho solto.

As regras do SCURL são sequenciais, sem executor interno. `max_rule_seconds` é um orçamento cooperativo, conferido antes e depois de cada regra; não interrompe uma função já iniciada. Falha de regra, prazo excedido ou ausência de cobertura válida devolvem erro técnico, sem classificação segura ou cache. `-t/--threads` continua aceito por compatibilidade, mas os metadados informam uma thread.

Cada análise de URL usa cookies próprios. O transporte fixa os endereços DNS aprovados por salto, preserva Host/SNI e a verificação TLS, e não usa proxies de ambiente. Endereços DNS mistos públicos/privados são recusados por padrão.

CORS permite apenas as origens listadas em `cors.allow_origins` (lista vazia por padrão; chamadas da mesma origem continuam funcionando). Para um frontend em outro domínio, configure sua origem exata, incluindo esquema e porta. WebSockets verificam a origem, a expiração e a revogação da sessão antes de transmitir mensagens e durante períodos ociosos.
