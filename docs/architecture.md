# Arquitetura do ScamLens

O ScamLens expõe uma REST API construída com FastAPI e servida por Uvicorn atrás de um reverse proxy Nginx. A API é a camada de entrada que orquestra os dois motores de análise — `scurl` (URLs) e `scqr` (QR codes) — e gerencia autenticação, quotas, cache e logging de requisições.

---

## Estrutura de diretórios

```
scamlens/
├── api/                    # Handlers de rota organizados por domínio
│   ├── analyze.py          # POST /analyze
│   ├── analyze_qr.py       # POST /analyze/qr
│   ├── auth.py             # /auth/*
│   ├── user.py             # /profile, /history
│   └── health.py           # /health
├── plugins/
│   ├── math/               # Utilitários matemáticos compartilhados
│   ├── scurl/              # Motor de análise de URLs
│   └── scqr/               # Motor de análise de QR codes
├── providers/              # I/O externo: HTTP, DNS, RDAP, SSL, SafeBrowsing, banco
├── middleware/
│   └── logging.py          # RequestLoggingMiddleware
└── scamLens/
    └── config.toml         # Configuração da aplicação
```

---

## Entrypoint e ciclo de vida

A aplicação é inicializada em `server.py` via o padrão `lifespan` do FastAPI com `@asynccontextmanager`. O contexto de startup configura o handler de log em arquivo no logger do Uvicorn e inicializa o banco. O contexto de shutdown garante flush dos logs e fechamento limpo das conexões.

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_file_logging()
    init_database()
    yield
    teardown_logging()

app = FastAPI(lifespan=lifespan)
```

Em produção (`SCAMLENS_ENV=production`), os endpoints `/docs` e `/redoc` são desabilitados automaticamente.

---

## Rotas

A API expõe cinco grupos de rotas:

| Grupo | Prefixo | Descrição |
|-------|---------|-----------|
| Análise de URL | `/analyze` | Submissão e resultado de análise de URLs |
| Análise de QR | `/analyze/qr` | Upload e análise de imagens com QR code |
| Autenticação | `/auth` | Registro, login, refresh, logout, verificação de email |
| Usuário | `/profile`, `/history` | Dados do usuário autenticado e histórico de scans |
| Health | `/health` | Liveness probe usado pelo Railway |

---

## Autenticação

### Estratégia de tokens

A API usa JWT de curta duração (access token) combinado com refresh token rotativo de longa duração. Ambos são transmitidos como **cookies httpOnly**, não via `Authorization` header.

| Token | Duração | Armazenamento servidor |
|-------|---------|----------------------|
| Access token (JWT) | 15 minutos | Sem estado — validado pela assinatura |
| Refresh token | 7 dias | Hash armazenado na tabela `AUTH_TOKENS` |

O frontend JS faz requisições com `credentials: "include"`. Como a API e o frontend são same-origin, os cookies são enviados automaticamente em toda requisição, sem necessidade de interceptar requests para injetar headers. Isso também elimina o vetor de roubo de token via `localStorage` em cenários de XSS.

### Fluxo

```
POST /auth/login
  → valida credenciais (bcrypt)
  → emite access JWT + refresh token
  → seta cookies httpOnly na resposta

Requisição autenticada
  → access token lido do cookie
  → validado via dependency get_current_user

POST /auth/refresh
  → valida hash do refresh token em AUTH_TOKENS
  → revoga o token atual
  → emite novo par, atualiza cookies

POST /auth/logout
  → marca refresh token como revogado
  → limpa cookies
```

### Proteção de rotas

Rotas protegidas declaram `Depends(get_current_user)`. A dependency decodifica o JWT, busca o usuário no banco e retorna o objeto `User`. Se o token estiver ausente, expirado ou inválido, levanta `HTTPException(401)` antes de o handler ser executado.

Rotas públicas não usam a dependency mas ainda são submetidas à quota anônima por IP.

### Verificação de email

No registro, um token de verificação é gerado, armazenado como hash em `USERS` e enviado por email via **Resend**. O endpoint `GET /auth/verify?token=...` valida o token (single-use) e marca `email_verified = true` no banco.

---

## Pipeline de análise de URL

O handler `POST /analyze` valida a quota do requisitante, consulta o cache e, em caso de miss, delega para `scurl.run_engine()`.

```
POST /analyze
      │
      ▼
check_quota         → quota anônima (por IP) ou autenticada (por user_id + plano)
      │
      ▼
cache_lookup        → SHA-256(url_normalizada) → hit retorna resultado direto
      │
      ▼
scurl.run_engine()  → validate_url → collect → execute → context_apply → score → response_builder
      │
      ▼
persist_result      → grava em SCANS, incrementa DAILY_USAGE / ANONYMOUS_QUOTA
      │
      ▼
return ScanResult
```

A consulta e a gravação no cache são feitas pela API, não pelo motor — `scurl` é stateless e não conhece o banco do ScamLens.

---

## Pipeline de análise de QR code

O handler `POST /analyze/qr` recebe um upload `multipart/form-data`, valida o arquivo, decodifica o QR e roteia o payload para o pipeline correspondente ao tipo detectado.

```
POST /analyze/qr
      │
      ▼
check_quota
      │
      ▼
validate_file       → magic bytes (não Content-Type): JPEG, PNG, GIF, WebP, SVG
      │
      ▼
scqr.decode()       → pyzbar (primário) → zxingcpp (fallback silencioso)
      │
      ▼
classify_qrcode     → detecta tipo: url, pix, email, phone, wifi, contact, calendar, sms, json, text
      │
      ▼
analyze_qrcode      → pipeline por tipo
      │              (payload url → scurl.run_engine())
      ▼
persist_result      → grava em QR_SCANS
      │
      ▼
return QrScanResult
```

### Validação de arquivo

O tipo do arquivo é determinado por **magic bytes**, não pelo `Content-Type` declarado pelo cliente, que é totalmente controlável pelo requisitante. SVGs são convertidos via `cairosvg` para PNG antes de serem passados ao decoder.

### Decoder com fallback

`pyzbar` é o decoder primário. Em caso de falha de decodificação, `zxingcpp` é tentado silenciosamente — ele tem suporte a mais variantes de QR mas causa crash por instrução AVX no hardware de produção atual (Pentium P6200, sem suporte a AVX). O fallback é encapsulado em `try/except` com supressão explícita do erro.

### Classificador de tipo

O classificador mapeia o payload decodificado para uma categoria antes de roteá-lo:

| Tipo | Critério de detecção |
|------|---------------------|
| `url` | Prefix `http://`, `https://`, `ftp://` |
| `pix` | Prefix `000201` (padrão EMV QR) |
| `email` | Prefix `MAILTO:` |
| `phone` | Prefix `TEL:` |
| `wifi` | Prefix `WIFI:` |
| `contact` | `BEGIN:VCARD` |
| `calendar` | `BEGIN:VEVENT` |
| `sms` | `SMSTO:` ou `SMS:` |
| `json` | JSON válido |
| `text` | Fallback |

Payloads do tipo `url` são delegados integralmente ao `scurl.run_engine()`, passando pelo pipeline completo de análise de URL.

---

## Rate limiting e quotas

O controle de uso opera em dois níveis independentes.

**Nível 1 — Rate limit por requisição** via `slowapi`. Aplicado por IP antes de qualquer lógica de negócio. Estouro retorna `429` com header `Retry-After`.

**Nível 2 — Quota diária** verificada no banco antes de executar a análise. Usuários anônimos são identificados por IP (`ANONYMOUS_QUOTA`); usuários autenticados por `user_id` (`DAILY_USAGE`). O limite diário de cada plano é lido dinamicamente da tabela `PLANS` — não é hardcoded.

```
Usuário anônimo:     máximo de 3 scans/dia por IP
Usuário autenticado: limite definido pelo plano (PLANS.daily_scan_limit)
```

Além disso, um `asyncio.Semaphore` limita o número de análises em execução simultânea, evitando que picos de tráfego saturem os providers externos:

```python
semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

async def analyze(...):
    async with semaphore:
        result = await run_engine(url)
```

---

## Cache

Resultados de análise são cacheados por `SHA-256(url_normalizada)` na tabela `URL_CACHE`. Um hit de cache retorna o resultado armazenado sem executar nenhum estágio do pipeline — nem coleta, nem heurísticas, nem scoring.

A chave SHA-256 garante que variações superficiais da mesma URL (trailing slash, capitalização de scheme) que normalizam para a mesma forma não gerem entradas duplicadas.

---

## Middleware de logging

`RequestLoggingMiddleware` intercepta todas as requisições HTTP no nível do ASGI, independente de rota ou resultado. Registra IP, método, path, status code, user-agent e latência em milissegundos na tabela `request_logs`.

Esse log é distinto do `API_LOGS`, que opera no nível de rota e inclui `user_id` e contexto de negócio (endpoint, resultado da operação). Os dois coexistem: `request_logs` para observabilidade de infraestrutura, `API_LOGS` para auditoria de uso.

---

## Banco de dados

O banco é SQLite em modo WAL (Write-Ahead Logging), rodando em volume persistente no Railway. WAL permite leituras concorrentes enquanto uma escrita está em andamento — relevante para uma API que lê histórico ao mesmo tempo em que grava novos resultados.

Conexões são **thread-local**: cada thread do pool do Uvicorn mantém sua própria conexão, contornando a restrição de afinidade de thread do SQLite sem necessidade de driver assíncrono.

### Esquema de tabelas

| Tabela | Descrição |
|--------|-----------|
| `PLANS` | Planos disponíveis com limites e features |
| `USERS` | Contas de usuário, hash de senha, referência ao plano |
| `AUTH_TOKENS` | Hash dos refresh tokens ativos e revogados |
| `SCANS` | Resultados de análises de URL por usuário |
| `QR_SCANS` | Resultados de análises de QR code por usuário |
| `DAILY_USAGE` | Contador de scans diários por usuário autenticado |
| `ANONYMOUS_QUOTA` | Contador de scans diários por IP anônimo |
| `URL_CACHE` | Cache de resultados por SHA-256 da URL normalizada |
| `API_LOGS` | Log de operações por rota com contexto de negócio |
| `request_logs` | Log de todas as requisições HTTP (middleware-level) |

---

## Infraestrutura e deploy

A aplicação roda no Railway em um único dyno. O Nginx faz TLS termination e serve arquivos estáticos do frontend diretamente, repassando requisições de API para o Uvicorn via proxy reverso.

Logs de arquivo são registrados via hooks no logger do Uvicorn, inicializados no contexto `lifespan`. Isso garante que o handler de arquivo esteja ativo antes de qualquer requisição ser processada e seja fechado corretamente no shutdown.

O endpoint `/docs` (Swagger UI gerado automaticamente pelo FastAPI) é desabilitado em produção via variável de ambiente `SCAMLENS_ENV=production`, evitando exposição do schema da API publicamente.