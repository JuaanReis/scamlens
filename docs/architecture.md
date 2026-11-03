# Arquitetura do ScamLens

O ScamLens disponibiliza uma API construída com FastAPI e servida por Uvicorn. A API orquestra os motores `scurl` (URLs e QR com URL), `scfs` (arquivos), `scpix` (Pix copia e cola) e `scimg` (imagens), além do chat autenticado por HTTP e WebSocket. Autenticação, cotas, histórico e logging ficam na camada da API e nos providers; o cache de análises pertence ao fluxo de URL.

---

## Estrutura de diretórios

```
scamlens/
├── api/
│   ├── router/
│   │   ├── auth.py          # /api/auth/*
│   │   ├── users.py         # /api/user/me, /avatar, /scans
│   │   ├── admin.py         # /api/admin/*, incluindo /health/version
│   │   ├── system.py        # /, /favicon.ico, /health
│   │   ├── runtime.py       # coordenação externa de execução dos motores
│   │   └── module/
│   │       ├── scurl/       # url.py, qr.py, scans.py e schema/
│   │       ├── scfs/        # file.py, scans.py e schema/
│   │       ├── scpix/       # pix.py, scans.py e schema/
│   │       ├── scimg/       # image.py e schema/; sem histórico
│   │       └── chat/        # mensagens HTTP e WebSocket
│   ├── middleware/
│   │   ├── auth.py          # autenticação de usuário/admin
│   │   ├── limiter.py       # rate limit por IP, rota e método
│   │   ├── quota.py         # reserva e devolução de cota
│   │   └── logging/         # middleware e persistência de requisições
│   └── server.py            # app, lifespan e montagem dos routers
├── plugins/
│   ├── scurl/               # análise de URL
│   │   └── vendor/scqr/     # decoder de QR integrado ao scurl
│   ├── scfs/                # análise estática de arquivos
│   ├── scpix/               # análise de BR Code Pix
│   └── scimg/               # heurísticas experimentais de imagem
├── providers/
│   ├── database/            # usuários, cotas, histórico e logs
│   └── math/                # utilitários matemáticos compartilhados
└── scamLens/
    ├── paths.py             # caminhos compartilhados
    └── config.toml          # configuração da aplicação
```

Os routers de negócio ficam em `api/router/module/`, separados dos motores em `plugins/`. O decoder `scqr` vive dentro de `plugins/scurl/vendor/scqr` e é usado pelo SCURL; a API monta sua rota em `/api/scurl/qr`. Arquivos, Pix e imagens possuem routers e motores próprios.

---

## Entrypoint e ciclo de vida

Inicializamos a aplicação em `server.py` via `lifespan`. Com `[logs].enabled`, o launcher define uma pasta compartilhada pela execução. Cada processo cria uma subpasta `process_<PID>` com seu arquivo JSON de eventos e rotação, além de um `host_info.txt` separado com o cabeçalho de informações da inicialização. No startup, o banco é inicializado (`init_db()`), o admin é garantido (`ensure_admin_exists()`) e o writer de requisições é iniciado. No shutdown, o writer drena seus lotes e fecha sua conexão; a fila de arquivo é esvaziada. O launcher fecha os handlers após o encerramento do Uvicorn e marca a pasta da sessão como concluída para a retenção.

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

As rotas de negócio usam o prefixo `/api`. `api/server.py` monta os routers de análise e histórico com seus prefixos; o router do chat já declara `/api/chat`.

| Grupo | Rotas registradas | Comportamento |
|-------|-------------------|---------------|
| URL | `POST /api/scurl/analyze/url` | JSON com URL; autenticação opcional |
| QR | `POST /api/scurl/qr/analyze/qr` | Upload `file`; somente QR com URL |
| Arquivos | `POST /api/scfs/analyze/file` | Upload `file`; análise estática, autenticação opcional |
| Pix | `POST /api/scpix/analyze/pix` | JSON com `payload` e `expected` opcional |
| Imagens | `POST /api/scimg/analyze/image` | Upload `file`; análise heurística experimental |
| Histórico URL/QR | `GET /api/scurl/scans`, `GET /api/scurl/scans/{identifier}` | Público; detalhe por ID ou hash da URL |
| Histórico de arquivos | `GET /api/scfs/scans`, `GET /api/scfs/scans/{scan_id}` | Autenticado; usuário vê seus resultados, admin vê todos |
| Histórico Pix | `GET /api/scpix/scans`, `GET /api/scpix/scans/{scan_id}` | Autenticado; usuário vê seus resultados, admin vê todos |
| Histórico do usuário | `GET /api/user/scans` | Somente resultados do usuário; filtro `module` |
| Chat HTTP | `GET /api/chat/messages`, `POST /api/chat/messages` | Histórico paginado e envio; autenticação obrigatória |
| Chat em tempo real | `WebSocket /api/chat/ws` | Recebe mensagens após autenticação |
| Autenticação | `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `POST /api/auth/refresh` | Cadastro e sessão |
| Usuário | `GET /api/user/me`, `POST /api/user/avatar` | Perfil, atividade e avatar |
| Administração | `/api/admin/metrics`, `/api/admin/users`, `/api/admin/scans`, `/api/admin/request-logs`, `/api/admin/logs` | Conta admin; histórico e filtros dos módulos suportados |
| Versão | `GET /api/admin/health/version` | Requer admin |
| Sistema | `GET /`, `GET /favicon.ico`, `GET /health` | Página, ícone e verificação do banco |

O SCIMG ainda não possui rotas de histórico. Os contratos de entrada, exemplos e códigos de resposta estão em [USAGE.md](USAGE.md).

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

`POST /api/scurl/analyze/url` valida a entrada, autentica opcionalmente e adquire a vaga do módulo. A cota é reservada atomicamente no SQLite antes do motor. O helper `api/router/runtime.py` coordena um único executor externo; o SCURL executa as regras sequencialmente, sem criar outro pool.

```
entrada → rate limit por IP/rota/método → validação/autenticação
        → vaga do módulo → reserva atômica da cota
        → run_scan → run_engine → HTTP/TLS com IP aprovado
        → regras sequenciais → cobertura/score → resposta/histórico
```

Erros normais devolvem a reserva. Cancelamentos após submissão mantêm a cobrança e a vaga até o trabalho terminar. Não há transação aberta durante a análise. `max_rule_seconds` é um prazo cooperativo entre chamadas de regras, sem interrupção forçada de uma regra já iniciada. Não há classificação segura sem cobertura numérica válida.

O cliente HTTP e os cookies pertencem à análise. A camada de transporte fixa o IP por origem, preserva Host/SNI e verificação do certificado, e valida os redirecionamentos. Cache legado do SCURL 2.0.0 é invalidado pela versão 2.0.1.

## Pipeline de análise de QR code

`POST /api/scurl/qr/analyze/qr` (em `api/router/module/scurl/qr.py`) lê os bytes do upload e chama **o mesmo `plugins.scurl.run_engine()`**, passando os bytes brutos como `source` e `use_cache=False`. Não há validação de magic bytes no nível do router, nem uma pipeline de QR separada da de URL — tudo acontece dentro de `run_engine`, no estágio `validate_input_qr`:

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

O decoder identifica vários tipos de payload, mas a rota de QR aceita somente `url`. Para analisar um Pix, o cliente deve enviar o BR Code copia e cola como JSON para `POST /api/scpix/analyze/pix`; a rota de QR não encaminha esse conteúdo ao SCPIX.

---

## Pipelines de arquivos, Pix e imagens

SCFS, SCPIX e SCIMG recebem suas entradas pelos routers em `api/router/module/`. Cada router aplica autenticação opcional, reserva cota e usa `api/router/runtime.py::run_scan` para chamar seu motor. O retorno HTTP de sucesso segue o envelope `{scan, target}`.

| Motor | Entrada e análise | Resultado e persistência |
|-------|-------------------|--------------------------|
| SCFS | Bytes e nome do upload; análise estática de PE, ELF, Mach-O e scripts suportados | `ok`, `partial` ou `inconclusive`; resultado salvo em `module_scans` pela API |
| SCPIX | BR Code em `payload` e referências opcionais em `expected` | `ok`, `partial` ou `inconclusive`; resultado salvo em `module_scans` pela API |
| SCIMG | Bytes e nome da imagem; decodificação com Pillow, coleta de métricas, heurísticas sequenciais e score | `ok` ou erro técnico; sem gravação no histórico |

SCFS não executa os arquivos recebidos. SCPIX não consulta cobranças dinâmicas nem confirma titularidade de chave. SCIMG aceita JPEG, PNG, WebP, BMP e TIFF com um único quadro e aplica os limites de `[scimg.scanner]`; sua pontuação é experimental e `ai_model.status` permanece `not_implemented`.

Os scanners de arquivos e imagens leem `[scfs.scanner]` e `[scimg.scanner]` em `scamLens/config.toml`. SCPIX usa `plugins/scpix/config.py::Settings`. Cada motor também pode ser chamado pelo entry point correspondente (`scfs`, `scpix`, `scimg`), sem a persistência automática feita pelos routers HTTP.

## Histórico dos módulos

URL e QR compartilham a tabela `scans`, com identificação por ID ou hash da URL. SCFS e SCPIX salvam resultados estruturados em `module_scans`; análises repetidas do mesmo alvo geram registros separados. A aplicação não persiste os arquivos enviados nem o payload Pix bruto.

`GET /api/scfs/scans` e `GET /api/scpix/scans` exigem autenticação, aceitam `limit`, `offset` e `target_hash`, e restringem a leitura ao dono, exceto para admins. Os detalhes usam `/{scan_id}` e retornam `{scan, target}`. Resultados anônimos desses módulos ficam acessíveis apenas a administradores.

`GET /api/user/scans` reúne os resultados do usuário, e `GET /api/admin/scans` permite consulta administrativa com filtro opcional por usuário. O filtro `module` aceita `scurl`, `scfs` e `scpix`. As métricas administrativas e a atividade do perfil usam esses históricos. O uso autenticado de SCIMG é contado em `daily_usage`, mas os resultados não participam de `module_scans`, dessas listas ou das métricas baseadas nelas.

## Chat

`api/router/module/chat/__init__.py` expõe `GET /api/chat/messages`, `POST /api/chat/messages` e `WebSocket /api/chat/ws`. Todas exigem usuário autenticado. O POST persiste conteúdo e horário em `chat_messages` antes do broadcast; o WebSocket recebe os eventos. As conexões em memória são locais ao processo, sem sincronização entre workers. Paginação, formato e exemplos estão em [USAGE.md](USAGE.md#chat).

## Rate limiting e quotas

Dois níveis independentes, ambos confirmados no código:

**Nível 1 — `slowapi`**, por IP, configurável via `config.toml` (`rate_limit.enabled`, `rate_limit.requests_per_minute`). Se desabilitado, o limite efetivo vira `99999/minute` (na prática, sem limite).

**Nível 2 — cota diária no banco**, configurada em `scamLens/config.toml`:

- Anônimo: `[quota].anonymous_daily_limit`, atualmente 3, contado por IP em `anonymous_quota` e compartilhado entre análises.
- Autenticado: `[quota.plans]`, atualmente `standard = 5`, `go_pro = 25` e `plus_premium = -1` (ilimitado), contado por `(user_id, module, date)` em `daily_usage`. URL e QR usam `scurl`; arquivos, Pix e imagens usam `scfs`, `scpix` e `scimg`.

Os limites são lidos pelos providers de cota; a tabela `plans` guarda nome, rótulo e preço. Cada scanner usa um `asyncio.Semaphore` com `rate_limit.max_concurrent_scans` (atualmente 20). URL e QR compartilham o mesmo semáforo; SCFS, SCPIX e SCIMG têm semáforos próprios. Uma rota sem vaga retorna `503`.

---

## Cache

Resultados são cacheados por `SHA-256` da URL (campo `url_hash UNIQUE` na tabela `scans`). Não utilizamos tabela `URL_CACHE` separada — cache e histórico de resultado são a mesma linha. Um hit (`find_by_hash`) devolve o resultado salvo sem rodar o pipeline de novo. No fluxo de QR, o cache é sempre ignorado (`use_cache=False` fixo no router).

---

## Middleware de logging

`RequestLoggingMiddleware` (em `api/middleware/logging/logging.py`) é um middleware ASGI registrado quando `[logs].enabled` está ativo. As entradas de arquivo e as linhas de `request_logs` têm filtros independentes e são enviadas a filas limitadas. Threads dedicadas fazem a escrita em blocos e o commit SQLite por lote, com retenção configurável. Respostas 4xx/5xx recebem níveis WARNING/ERROR; falhas sem resposta também são registradas. O outro registro de auditoria é `admin_audit_log`, que registra ações administrativas (`read_users`, `set_active`, `change_plan`, `read_scans`, `read_logs`, `list_logs`, `read_log`).

O filtro `module` de `GET /api/admin/request-logs` aceita `scurl`, `scqr`, `scfs`, `scpix` e `chat`. A classificação de QR é feita pelo prefixo `/api/scurl/qr`; seus resultados continuam no histórico de URL. SCIMG ainda não tem classificação própria nesse filtro, e `/api/scimg` não está nos prefixos padrão de `[logs.database]`. Logs de requisição e histórico de análises são registros separados.

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
| `module_scans` | resultados estruturados de SCFS e SCPIX, com dono, hash, status e payload `{scan, target}` |
| `chat_messages` | mensagens da sala comum, remetente e horários |
| `daily_usage` | contador por `(user_id, module, date)` |
| `anonymous_quota` | contador por IP |
| `request_logs` | log de requisições HTTP (IP, endpoint, método, user_id, scan_id, status, timestamp) |
| `admin_audit_log` | log de ações administrativas |

Não utilizamosm tabelas `AUTH_TOKENS`, `QR_SCANS`, `URL_CACHE` ou `API_LOGS`.

---

## Infraestrutura e deploy

Railway + Nginx (TLS termination, arquivos estáticos do frontend, proxy reverso pro Uvicorn) — não verificado linha a linha nesta auditoria (fora do repo do backend), mantido do documento anterior por ser consistente com o restante do projeto.

`/docs`, `/redoc` e `/openapi.json` são desabilitados em produção via `SCAMLENS_ENV=production`, confirmado em `scamLens/__init__.py::get_settings()`.
