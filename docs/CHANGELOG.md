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

## [1.8.0]

### Adicionado

- Logging de requisições HTTP reorganizado em módulos para identificação do cliente, persistência no banco e middleware
- Registro detalhado das requisições do scanner, incluindo método, URL sanitizada, status, tentativas, duração, IP, usuário e user-agent
- Sanitização de parâmetros sensíveis (`key`, `api_key`, `apikey`, `token` e `access_token`) nas URLs registradas em log
- Nova função HTTP genérica para requisições `GET` e `POST`, com suporte a payload JSON, retries e backoff
- Resultado HTTP extraído para módulo próprio, incluindo headers, corpo, tempo de resposta e cadeia de redirecionamentos
- Configuração centralizada de timeout, conexão, leitura, limite de conexões, redirecionamentos e rotação de user-agent no cliente HTTP
- Desativação do seguimento automático de redirecionamentos no cliente HTTP, mantendo o controle de redirecionamentos no scanner
- Restrição da leitura de arquivos do painel administrativo a arquivos `.log` existentes dentro do diretório de logs
- Ajuste do limite de concorrência do scanner de URLs de 5 para 3 threads

## [1.9.5]

### Adicionado

- Logging estruturado para consultas DNS, incluindo quantidades de registros A, AAAA, MX, NS, CNAME e TXT, além dos indicadores SPF, DMARC e DKIM
- Logging estruturado para consultas RDAP, cobrindo cache hit, cache miss, status HTTP, timeouts e falhas de conexão
- Logging estruturado para consultas SSL/TLS, incluindo versão TLS, cipher, emissor, SANs, validade, certificado autoassinado e status de OCSP
- Configuração do tamanho máximo de arquivos do `scfs` em `scamLens/config.toml`, com valor padrão de 50.000.000 bytes
- Configuração de nível e ativação dos logs por meio da seção `[logs]`

### Alterado

- Versão do pacote atualizada para `1.9.5`
- Constantes de caminhos estáticos e de logs tornadas públicas como `STATIC` e `LOG_DIR`
- Configuração de origens permitidas do CORS lida diretamente de `cors.allow_origins`
- Entropia do domínio arredondada para cinco casas decimais na resposta da análise de URL
- Consultas RDAP com HTTP/2 desativado e limites de concorrência por servidor ajustados de 8 para 16 e de 4 para 8 no fallback
- Consultas RDAP passaram a identificar o servidor e verificar o cache antes de adquirir o semáforo de concorrência
- Falhas de timeout e de pool no RDAP deixaram de ser armazenadas no cache, e a limpeza do cache passou a registrar a quantidade de entradas removidas
- Mensagens de logging do cliente HTTP padronizadas para o formato em inglês
- Documentação da arquitetura atualizada para refletir os novos nomes das constantes de caminho

### Removido

- Scripts de benchmark de conexão HTTP e RDAP (`scripts/benchmark/connection_benchmark.py` e `scripts/benchmark/rdap_connection_benchmark.py`)
