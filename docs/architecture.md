# Arquitetura do ScamLens

O ScamLens disponibiliza uma REST API construída com FastAPI e servida por Uvicorn atrás de um reverse proxy Nginx. A API orquestra o motor `scurl` (análise de URL), que por sua vez incorpora internamente o decoder de QR code (`scqr`, vendorizado), e gerencia autenticação, quotas, cache e logging de requisições.

---

## Estrutura de diretórios

```
scamlens/
├── api/
│   ├── router/
│   │   ├── auth.py          # /api/auth/* (register, login, logout, refresh)
│   │   ├── users.py         # /api/user/* (me, avatar)
│   │   ├── admin.py         # /api/admin/* (metrics, users, scans, logs)
│   │   ├── system.py        # /, /favicon.ico, /health, /health/version
│   │   └── scurl/
│   │       ├── url.py       # POST /analyze/url (montado em /api/scurl)
│   │       ├── qr.py        # POST /analyze/qr (montado em /api/scurl/qr)
│   │       └── scans.py     # GET /scans, /scans/{id} (montado em /api/scurl)
│   ├── middleware/
│   │   ├── auth.py          # get_current_user / get_current_admin
│   │   └── logging.py       # RequestLoggingMiddleware
│   ├── limiter.py            # instância slowapi
│   ├── path.py                # _STATIC, _STORAGE, _LOG_DIR
│   └── server.py              # monta a app, lifespan, inclui routers
├── plugins/
│   ├── math/                 # utilitários compartilhados (levenshtein, entropy, etc.)
│   ├── scfs/                 # motor de scan de arquivos (CLI + engine próprios, não exposto pela API ainda)
│   └── scurl/                # motor de análise de URL
│       └── vendor/scqr/      # decoder de QR code, vendorizado dentro do scurl
├── providers/                 # I/O externo: HTTP, DNS, RDAP, SSL, SafeBrowsing, banco
└── scamLens/
    └── config.toml            # configuração da aplicação
```

`plugins/scqr` como motor irmão de `scurl` **não existe** — o scqr vive dentro de `plugins/scurl/vendor/scqr` e é chamado internamente pelo pipeline do scurl, não pela API diretamente. `plugins/scfs` existe e tem CLI e engine próprios, mas nenhuma rota da API o expõe hoje.

---

## Entrypoint e ciclo de vida

Inicializamos a aplicação em `server.py` via `lifespan`. No startup, se `server.logs` estiver habilitado no `config.toml`, os handlers de log de arquivo são plugados nos loggers do uvicorn/fastapi; em seguida o banco é inicializado (`init_db()`) e o admin é garantido (`ensure_admin_exists()`). Não há rotina de shutdown/teardown — o bloco após o `yield` é vazio.

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    if LOGS_ENABLED:
        setup_logging_once(SESSION_LOG_FILE)
    init_db()
    conn = get_connection()
    ensure_admin_exists(conn)
    yield
```

Em produção (`SCAMLENS_ENV=production`), `docs_url`, `openapi_url` e `redoc_url` são setados para `None` na construção do `FastAPI(...)`.

---

## Rotas

Todas as rotas de negócio vivem sob prefixo `/api`. Não utilizamosm `/analyze`, `/auth` ou `/profile` na raiz — quem tentar chamar assim recebe 404.

| Grupo | Prefixo real | Descrição |
|-------|--------------|-----------|
| Análise de URL | `POST /api/scurl/analyze/url` | Submissão de URL para análise |
| Análise de QR | `POST /api/scurl/qr/analyze/qr` | Upload de imagem, extração de URL do QR e análise |
| Consulta de scans | `GET /api/scurl/scans`, `GET /api/scurl/scans/{id}` | Histórico público de scans |
| Autenticação | `/api/auth/register`, `/login`, `/logout`, `/refresh` | Não utilizamos endpoint de verificação de e-mail |
| Usuário | `GET /api/user/me`, `POST /api/user/avatar` | Perfil e avatar do usuário autenticado |
| Admin | `/api/admin/metrics`, `/users`, `/scans`, `/request-logs`, `/logs`, `/logs/{filename}` | Painel administrativo, tudo com log de auditoria |
| Sistema | `GET /`, `GET /favicon.ico`, `GET /health`, `GET /health/version` (admin) | Health check e liveness |

---

## Autenticação

### Estratégia de tokens

JWT de curta duração (access) + JWT de longa duração (refresh), ambos autocontidos e assinados com `HS256`. Transmitidos como cookies httpOnly, **mas o middleware também aceita `Authorization: Bearer <token>` como fallback** para o access token — não é cookie-only como poderia parecer.

| Token | Duração | Revogação |
|-------|---------|-----------|
| Access token (JWT) | 30 minutos | Verificada via blocklist de `jti` em `revoked_tokens` no logout |
| Refresh token | 30 dias (`remember=true`) ou 1 dia (`remember=false`) | Idem — `jti` inserido em `revoked_tokens` no logout, não há tabela de tokens ativos |

Não utilizamos uma tabela de tokens ativos com hash do refresh token. O refresh token é stateless (JWT); o servidor só guarda uma **lista de `jti` revogados** (`revoked_tokens`, com `expires_at` para permitir limpeza via `purge_expired_tokens()`). Ou seja, a validade de um refresh token não revogado nunca é checada contra o banco — só a assinatura e o `exp` do JWT.

### Fluxo real

```
POST /api/auth/register
  → hash da senha (bcrypt), cria usuário, seta cookies (remember=False)

POST /api/auth/login
  → busca usuário por email; se não existir, ainda roda bcrypt contra um hash
    dummy (_DUMMY_HASH) para não vazar timing de "email existe vs não existe"
  → verifica is_active
  → seta cookies (access_token, refresh_token)

Requisição autenticada
  → get_current_user lê cookie access_token OU header Authorization: Bearer
  → decode_token valida assinatura/tipo; se refresh, checa jti em revoked_tokens
  → busca usuário no banco, checa is_active

POST /api/auth/refresh
  → decodifica o refresh token (sem lookup em tabela de refresh ativos)
  → emite novo par de tokens

POST /api/auth/logout
  → revoga jti do access token e do refresh token em revoked_tokens
  → limpa os dois cookies
```

### Verificação de e-mail

**Não utilizamos no código atual.** Não há endpoint `/verify`, não há coluna `email_verified` em `users`, e não há integração com Resend nesta versão do repositório. Se isso já foi implementado em algum branch/versão anterior, não está no `main` hoje — não consideramos esse recurso como parte da versão atual.

---

## Pipeline de análise de URL

`POST /api/scurl/analyze/url` roda em `api/router/scurl/url.py`, chamando `plugins.scurl.run_engine()` dentro de um `run_in_executor` (a engine é síncrona) e sob um `asyncio.Semaphore(20)`. Se o semáforo já estiver saturado (`.locked()`), o handler devolve `503` **antes mesmo de tentar adquiri-lo** — ou seja, sob carga alta ele já recusa de cara em vez de enfileirar.

```
POST /api/scurl/analyze/url
      │
      ▼
rejeita URL > 100 caracteres (422)
      │
      ▼
tenta autenticar (get_current_user); falha silenciosa → tratado como anônimo
      │
      ▼
anônimo: is_quota_exceeded(ip)      → 401 se estourou (3/dia hardcoded)
autenticado: is_usage_exceeded(...) → 429 se estourou o limite do plano
      │
      ▼
se semáforo já lotado → 503 imediato
      │
      ▼
run_engine(url, use_cache=...)   → validate_input_qr → validate_url → collect
                                    → execute_rules → score → build_response
                                    (a própria engine já persiste o resultado
                                     via providers.database.cache dentro dela)
      │
      ▼
increment_usage / increment_anonymous_count
      │
      ▼
save_scan() é chamado de novo pelo router (best-effort, com try/except mudo)
      │
      ▼
return AnalyzeResponse
```

**Atualmente, a arquitetura foi projetada de forma que:** `scurl` não é stateless em relação ao banco. `plugins/scurl/engine/main.py` importa `providers.database.cache` e chama `persist_scan()` diretamente dentro do próprio `run_engine()`. O router então chama `save_scan()` de novo depois. Atualmente mantemos essa duplicação de persistência por compatibilidade, com intenção de centralizar essa responsabilidade futuramente — pretendemos revisar se é intencional (idempotência via `url_hash UNIQUE`?) ou dívida técnica.

Não utilizamos uma tabela `URL_CACHE` separada: cache e resultado persistido são a mesma linha na tabela `scans` (`url_hash UNIQUE`), consultada por `find_by_hash()`.

---

## Pipeline de análise de QR code

`POST /api/scurl/qr/analyze/qr` (em `api/router/scurl/qr.py`) lê os bytes do upload e chama **o mesmo `plugins.scurl.run_engine()`**, passando os bytes brutos como `source` e `use_cache=False`. Não há validação de magic bytes no nível do router, nem uma pipeline de QR separada da de URL — tudo acontece dentro de `run_engine`, no estágio `validate_input_qr`:

```
run_engine(bytes)
      │
      ▼
validate_input_qr(source)
      │
      ├─ se source já é uma URL string → passa direto
      │
      └─ se é bytes → plugins.scurl.vendor.scqr.engine.main.run_engine(data)
              │
              ▼
        scqr decodifica e classifica o tipo do QR
              │
              ▼
        qr_type != "url"  → erro "unsupported_qr_type" (fluxo TERMINA aqui)
        qr_type == "url"  → extrai a URL decodificada
              │
              ▼
segue o pipeline normal de análise de URL (validate_url → collect → ... )
```

**Isso é a divergência mais importante do documento anterior:** o `scqr` de fato classifica múltiplos tipos de payload (pix, email, phone, wifi, contact, calendar, sms, json, text — isso existe no vendor), mas **a integração atual com a API só aceita o tipo `url`**. QR codes de Pix, vCard, Wi-Fi etc. são decodificados e depois **rejeitados com erro**, não analisados. Se o suporte a outros tipos é uma feature planejada, ela não está ligada na API hoje.

---

## Rate limiting e quotas

Dois níveis independentes, ambos confirmados no código:

**Nível 1 — `slowapi`**, por IP, configurável via `config.toml` (`rate_limit.enabled`, `rate_limit.requests_per_minute`). Se desabilitado, o limite efetivo vira `99999/minute` (na prática, sem limite).

**Nível 2 — quota diária no banco**, com duas fontes de verdade diferentes:
- Anônimo: `ANONYMOUS_LIMIT = 3`, **hardcoded em `providers/database/quota.py`**, contado por IP em `anonymous_quota`.
- Autenticado: `PLAN_LIMITS = {"standard": 5, "go_pro": 25, "plus_premium": None}`, **também hardcoded em Python**, em `providers/database/usage.py`, contado por `(user_id, module, date)` em `daily_usage`.

A tabela `plans` **não tem coluna de limite** (só `name`, `label`, `price`). Ou seja, mudar o limite de um plano hoje exige editar código e fazer deploy, não é dado de configuração/banco. Se a intenção é permitir configurar isso sem deploy, essa é uma dívida real a resolver.

Além disso, `MAX_CONCURRENT_SCANS = 20` limita análises simultâneas via `asyncio.Semaphore`, com verificação de `.locked()` antes de tentar entrar (retorna 503 em vez de enfileirar/esperar).

---

## Cache

Resultados são cacheados por `SHA-256` da URL (campo `url_hash UNIQUE` na tabela `scans`). Não utilizamos tabela `URL_CACHE` separada — cache e histórico de resultado são a mesma linha. Um hit (`find_by_hash`) devolve o resultado salvo sem rodar o pipeline de novo. No fluxo de QR, o cache é sempre ignorado (`use_cache=False` fixo no router).

---

## Middleware de logging

`RequestLoggingMiddleware` (em `api/middleware/logging.py`) só é registrado se `server.logs` estiver habilitado no `config.toml`. Grava em `request_logs`. **Não utilizamos uma tabela `API_LOGS` separada** para contexto de negócio por rota — o único log de requisição é o `request_logs`, e o único outro log estruturado é `admin_audit_log`, que registra ações administrativas (`read_users`, `set_active`, `change_plan`, `read_scans`, `read_logs`, `list_logs`, `read_log`), não uso geral da API por usuários comuns.

---

## Banco de dados

SQLite, com `init_db()` cuidando de schema + migrações (ordem: schema antes de migrations). Conexões são obtidas via `get_connection()` em `providers/database/connection.py` (thread-local, conforme documentado anteriormente e não contestado aqui).

### Esquema de tabelas real (nomes exatamente como estão no `.sql`, minúsculos)

| Tabela | Descrição |
|--------|-----------|
| `plans` | `id, name, label, price, created_at` — sem coluna de limite de uso |
| `users` | conta, hash de senha, `plan_id`, `is_active` — sem `email_verified` |
| `revoked_tokens` | blocklist de `jti` revogados (access e refresh), com `expires_at` para purga |
| `scans` | resultado de análise de URL, `url_hash UNIQUE` — funciona como cache e histórico ao mesmo tempo |
| `daily_usage` | contador por `(user_id, module, date)` |
| `anonymous_quota` | contador por IP |
| `request_logs` | log de requisições HTTP (IP, endpoint, método, user_id, scan_id, status, timestamp) |
| `admin_audit_log` | log de ações administrativas |

Não utilizamosm tabelas `AUTH_TOKENS`, `QR_SCANS`, `URL_CACHE` ou `API_LOGS`.

---

## Infraestrutura e deploy

Railway + Nginx (TLS termination, arquivos estáticos do frontend, proxy reverso pro Uvicorn) — não verificado linha a linha nesta auditoria (fora do repo do backend), mantido do documento anterior por ser consistente com o restante do projeto.

`/docs`, `/redoc` e `/openapi.json` são desabilitados em produção via `SCAMLENS_ENV=production`, confirmado em `scamLens/__init__.py::get_settings()`.