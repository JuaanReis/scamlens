## [0.0.1 - 1.5.0]

### Adicionado

- API REST em FastAPI com Uvicorn, deploy previsto para Railway atrás de Nginx
- Autenticação JWT (access + refresh), cookies httpOnly com fallback via header `Authorization: Bearer`
- Revogação de tokens via blocklist de `jti` (`revoked_tokens`), sem tabela de tokens ativos
- Mitigação de timing attack no login (hash bcrypt dummy quando o e-mail não existe)
- Endpoints de auth: `POST /api/auth/register`, `/login` (com `remember`), `/logout`, `/refresh`
- Seed automático de conta admin no startup via `EMAIL_ADMIN`/`PASSWORD_ADMIN`
- Motor de análise de URL (`scurl`) com pipeline em estágios: `validate_url → collect → target_structure → context_apply → execute → score → response_builder`
- Heurísticas de URL, HTML e servidor registradas via decorador `@register`
- Scoring por dependências declarativas (`{op, val}`, redução multiplicativa) + média ponderada + sigmoide
- Providers externos: HTTP, DNS, RDAP, SSL/TLS, Google Safe Browsing
- Endpoint `POST /api/scurl/analyze/url`, com limite de concorrência via `asyncio.Semaphore` (retorna 503 sob saturação)
- Cache de resultado por `SHA-256` da URL normalizada, reaproveitando a própria tabela de scans (`url_hash UNIQUE`)
- Análise de QR code integrada ao mesmo motor do `scurl` — decoder `scqr` (vendorizado) com `pyzbar` como primário e `zxingcpp` como fallback silencioso
- Endpoint `POST /api/scurl/qr/analyze/qr` (hoje só processa QR codes cujo payload seja uma URL)
- Classificador de payload de QR no `scqr` cobrindo pix, e-mail, telefone, wifi, vCard, evento de calendário, SMS e JSON (decodifica, mas ainda não roteado para análise na API)
- Endpoints de consulta de histórico: `GET /api/scurl/scans`, `GET /api/scurl/scans/{id}`
- Quota de uso em dois níveis: rate limit por IP via `slowapi`, e quota diária por IP (anônimo) ou por plano (autenticado)
- Planos de assinatura (`standard`, `go_pro`, `plus_premium`) com limites diários definidos em código
- Perfil de usuário: `GET /api/user/me` com atividade agregada, `POST /api/user/avatar` com validação por magic bytes
- Painel administrativo: métricas, listagem/gestão de usuários (ativar/desativar, trocar plano), listagem de scans, logs de requisição e leitura de arquivos de log com proteção contra path traversal
- Log de auditoria administrativa (`admin_audit_log`) para toda ação do painel admin, inclusive leituras
- Middleware de log de requisições HTTP (`request_logs`), condicionado a `[server].logs` no `config.toml`
- Health check público (`/health`) e endpoint de versão restrito a admin (`/health/version`)
- Banco SQLite em modo WAL com conexões thread-local e inicialização de schema + migrações
- CLI `scurl` (via `pip install -e .`) com flags de threads, timeout, retries, cache, saída em arquivo/stdout e cores ANSI configuráveis
- Motor `scfs` (scan de arquivos) como módulo interno, ainda sem rota na API nem CLI publicado
- Configuração runtime centralizada via `config.toml` (server, CORS, cache, rate limit, cookies)
- Desabilitação automática de `/docs`, `/redoc` e `/openapi.json` em produção (`SCAMLENS_ENV=production`)