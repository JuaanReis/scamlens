# Uso do ScamLens

Este documento cobre como rodar a API localmente, como chamar cada endpoint (com exemplos reais de `curl`) e como usar o CLI `scurl`. Tudo aqui foi conferido contra o código em `main`, não contra o que estava planejado — se um comportamento parecer estranho, é porque é assim que o código faz hoje, e está marcado como tal.

---

## 1. Rodando a API localmente

### Variáveis de ambiente obrigatórias

`scamLens/__init__.py::get_settings()` lê essas variáveis via `os.environ[...]` — **sem elas a aplicação não sobe** (`KeyError` na inicialização):

```bash
EMAIL_ADMIN=admin@exemplo.com
PASSWORD_ADMIN=uma_senha_forte
JWT_SECRET=uma_chave_secreta_longa
GOOGLE_SAFE_BROWSING_KEY=sua_chave_da_google_safe_browsing_api
```

Opcional:

```bash
SCAMLENS_DB_PATH=./providers/database/storage/db/scamlens.db   # default se omitido
SCAMLENS_ENV=development   # default é "production"; afeta /docs, /redoc, /openapi.json
```

Essas variáveis podem ir num `.env` na raiz — `get_settings()` chama `load_dotenv()` antes de ler o `environ`.

`EMAIL_ADMIN`/`PASSWORD_ADMIN` não são só config: `ensure_admin_exists()` roda no `lifespan` e **cria essa conta como admin automaticamente** se ela ainda não existir no banco. É assim que você ganha acesso às rotas `/api/admin/*` num ambiente novo.

### Subindo o servidor

```bash
pip install -e .
scamlens-api
```

Isso chama `run()` em `api/server.py`, que lê `[server]` de `scamLens/config.toml` (`host`, `port`, `workers`, `reload`). Com o `config.toml` do repo, sobe em `0.0.0.0:5300` com reload ativado. Em Windows, `workers` é forçado para `1` independente do config (checagem de `sys.platform == "win32"`).

Alternativa sem instalar o pacote:

```bash
uvicorn api.server:app --reload --port 5300
```

### Ambiente local vs produção — coisas que vão te morder

- `config.toml` traz `[cookies] secure = true`. Em `http://localhost` (sem TLS), navegadores **não vão enviar de volta** um cookie `Secure`. Testando via `curl`, isso não é problema (curl ignora a flag), mas testando via browser/frontend local, os cookies de auth simplesmente não vão persistir a menos que você rode atrás de HTTPS ou baixe `secure` pra `false` localmente.
- `[cors] allow_origins = ["*"]` junto com `allow_credentials = true` é uma combinação que a spec de CORS não permite de fato funcionar com credenciais em navegador (wildcard + credentials é rejeitado pelo browser). Se o frontend depender de cookies cross-origin, isso vai falhar silenciosamente — configure `allow_origins` com a origem exata em vez de `*` para esse caso.
- `[rate_limit] enabled = true`, `requests_per_minute = 10` no config do repo — bem baixo para testes manuais repetidos via curl/Postman. Se for só testar localmente, pode desabilitar (`enabled = false`) ou subir o número, dentro do `[rate_limit]` do `config.toml`.

### Documentação interativa

Com `SCAMLENS_ENV` diferente de `production` (ou seja, definida como qualquer outra coisa, ex. `development`), `/docs` (Swagger) e `/redoc` ficam disponíveis. Em produção (`SCAMLENS_ENV=production`, que é o **default** se a variável não for setada), essas rotas ficam desligadas — `docs_url=None` etc. na construção do `FastAPI(...)`.

---

## 2. Autenticação

### Registrar

```bash
curl -X POST http://localhost:5300/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@exemplo.com", "name": "Fulano", "password": "senha123"}'
```

Resposta (`201`):
```json
{"id": 1, "email": "user@exemplo.com", "name": "Fulano"}
```
Se o e-mail já existir, `409`. **Não há verificação de e-mail** — a conta já nasce utilizável. Cookies `access_token`/`refresh_token` já são setados na resposta (com `remember=false`, então o refresh dura 1 dia).

### Login

```bash
curl -X POST http://localhost:5300/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "user@exemplo.com", "password": "senha123", "remember": true}'
```

`remember: true` faz o refresh token durar 30 dias em vez de 1. Resposta: `{"ok": true}`, mais os cookies. Credenciais inválidas → `401`; conta desativada (`is_active=false`, setável só via admin) → `403`.

Use `-b cookies.txt -c cookies.txt` no curl para reaproveitar os cookies nas próximas chamadas.

### Autenticar sem cookies (Bearer)

O middleware aceita `Authorization: Bearer <access_token>` como alternativa ao cookie — útil para chamar a API de scripts/Postman sem lidar com cookie jar:

```bash
curl http://localhost:5300/api/user/me \
  -H "Authorization: Bearer <access_token_copiado_do_cookie>"
```

### Renovar token

```bash
curl -X POST http://localhost:5300/api/auth/refresh -b cookies.txt -c cookies.txt
```
Emite um novo par de tokens a partir do refresh token do cookie. **Não há checagem contra uma tabela de refresh tokens ativos** — só a assinatura/expiração do JWT são validadas, mais o `jti` não estar na blocklist de revogados.

### Logout

```bash
curl -X POST http://localhost:5300/api/auth/logout -b cookies.txt
```
Revoga o `jti` do access e do refresh token atuais (inserindo em `revoked_tokens`) e limpa os cookies.

---

## 3. Análise de URL

```bash
curl -X POST http://localhost:5300/api/scurl/analyze/url \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"url": "http://exemplo-suspeito.com/login", "use_cache": true}'
```

Sem cookies/Bearer, a chamada roda como anônima (limite de 3/dia por IP, hardcoded). Autenticado, o limite vem de `PLAN_LIMITS` (hardcoded em Python, não configurável pelo banco):

| Plano | Limite diário |
|-------|---------------|
| `standard` | 5 |
| `go_pro` | 25 |
| `plus_premium` | ilimitado (`None`) |

Respostas possíveis:
- `200` — `AnalyzeResponse` com `scan` (score, risk_level, verdict, heurísticas disparadas, insights) e `target` (identidade, rede, TLS, DNS, HTTP, conteúdo, WHOIS/domínio).
- `422` — URL com mais de 100 caracteres, ou corpo inválido.
- `401` — limite anônimo estourado.
- `429` — limite diário do plano estourado (autenticado).
- `503` — servidor com as 20 análises concorrentes já em execução (`MAX_CONCURRENT_SCANS`); ele **não enfileira**, rejeita na hora.
- `400` — erro interno do motor (`scan.status == "error"`), corpo no formato `ErrorResponse`.

`use_cache: true` só faz efeito se `[cache].enabled = true` no `config.toml` do `scurl` também estiver ligado. Um hit de cache é a mesma linha da tabela `scans` de uma análise anterior (não há cache separado).

---

## 4. Análise de QR code

```bash
curl -X POST http://localhost:5300/api/scurl/qr/analyze/qr \
  -b cookies.txt \
  -F "file=@qrcode.png"
```

**Só funciona para QR codes cujo conteúdo seja uma URL `http://` ou `https://`.** QR codes de Pix, vCard, Wi-Fi, e-mail, telefone, evento de calendário, SMS ou JSON são decodificados internamente pelo `scqr`, mas a integração atual rejeita qualquer tipo que não seja `url`, retornando `400` com `error.type = "unsupported_qr_type"`. Se você esperava suporte a Pix/vCard/etc., não está ligado nessa versão.

Cache é sempre ignorado nesse endpoint (`use_cache=False` fixo no código, não configurável via request).

Erros específicos desse endpoint:
- `undetected_qr_code` — nenhum QR encontrado na imagem.
- `unsupported_qr_type` — QR válido, mas não é do tipo `url`.
- `empty_qr_data` — QR de tipo `url` mas sem conteúdo decodificável.
- `415` — formato de arquivo não reconhecido (validação por magic bytes, não por `Content-Type` do multipart).

---

## 5. Consultar scans

```bash
curl "http://localhost:5300/api/scurl/scans?limit=20&offset=0"
curl "http://localhost:5300/api/scurl/scans/<scan_id_ou_url_hash>"
```

`GET /api/scurl/scans` **não filtra por usuário** — devolve o histórico de scans em geral (`limit` 1–200, default 50), não é "meu histórico". Para dados do usuário logado, veja `/api/user/me` abaixo, que expõe atividade agregada (contagem semanal, total, ameaças) via `activity`.

---

## 6. Perfil de usuário

```bash
curl http://localhost:5300/api/user/me -b cookies.txt
```

```bash
curl -X POST http://localhost:5300/api/user/avatar \
  -b cookies.txt \
  -F "file=@foto.jpg"
```
Limite de 2MB, formatos aceitos por magic bytes: JPEG, PNG, WebP, GIF. Avatar antigo é apagado do disco ao trocar.

---

## 7. Administração

Requer conta com `is_admin = true` — só existe hoje por seeding automático via `EMAIL_ADMIN`/`PASSWORD_ADMIN` no startup, não há endpoint para promover um usuário a admin.

```bash
curl http://localhost:5300/api/admin/metrics -b admin_cookies.txt
curl "http://localhost:5300/api/admin/users?limit=50&offset=0" -b admin_cookies.txt
curl -X PATCH http://localhost:5300/api/admin/users/3/active \
  -H "Content-Type: application/json" -b admin_cookies.txt \
  -d '{"is_active": false}'
curl -X PATCH http://localhost:5300/api/admin/users/3/plan \
  -H "Content-Type: application/json" -b admin_cookies.txt \
  -d '{"plan_name": "go_pro"}'
curl "http://localhost:5300/api/admin/scans?limit=50" -b admin_cookies.txt
curl "http://localhost:5300/api/admin/request-logs?limit=200" -b admin_cookies.txt
curl http://localhost:5300/api/admin/logs -b admin_cookies.txt
curl "http://localhost:5300/api/admin/logs/scamlens_2026-07-27_10-00-00_pid1234.log?tail=500" -b admin_cookies.txt
```

`plan_name` válido: `standard`, `go_pro`, `plus_premium` (qualquer outro valor → `400`). Toda ação admin (inclusive leituras de listas) grava uma linha em `admin_audit_log` — isso inclui simplesmente listar usuários ou scans, não só ações de escrita.

`GET /api/admin/logs/{filename}` só existe se `[server].logs = true` no `config.toml` (senão não há arquivos de log pra listar) e só serve arquivos dentro do diretório de log — tentativa de path traversal (`../`) retorna `400`.

---

## 8. Health check

```bash
curl http://localhost:5300/health
curl http://localhost:5300/health/version -b admin_cookies.txt   # requer admin
```

`/health` não requer autenticação e testa conectividade com o banco (`db: "ok"` ou `"error"`). `/health/version` requer admin e devolve a versão do pacote instalado.

---

## 9. CLI `scurl`

Depois de `pip install -e .`, o comando `scurl` fica disponível (`plugins.scurl.cli.main:main`):

```bash
scurl https://exemplo.com
scurl -u https://exemplo.com          # equivalente, forma explícita
scurl https://exemplo.com -v          # verbose
scurl https://exemplo.com -t 4        # 4 threads no coletor
scurl https://exemplo.com -T 10       # timeout de 10s (NÃO é threads — cuidado, é flag diferente do scurl vs projetos como pepeScraper)
scurl https://exemplo.com -o resultado.json
scurl https://exemplo.com -o -        # imprime o JSON no stdout em vez de tabela formatada
scurl https://exemplo.com -c          # usa cache (chama init_db() antes de rodar)
scurl https://exemplo.com -dc         # desabilita cores ANSI na saída
```

Flags reais (`plugins/scurl/cli/args.py`):

| Flag | Significado | Default |
|------|-------------|---------|
| `-u/--url` ou posicional | URL alvo (um ou outro, não os dois) | — |
| `-v/--verbose` | saída detalhada | `false` |
| `-t/--threads` | threads do coletor | `1` |
| `-T/--timeout` | timeout de rede em segundos | `5` |
| `-k` | parâmetro do scoring (ver `calculate_score`) | `5` |
| `-r/--retries` | tentativas de coleta | `3` |
| `-o/--output` | salva JSON em arquivo, ou `-` para stdout | — |
| `-c/--cache` | usa cache (e inicializa o banco antes) | `false` |
| `-dc/--disable-color` | desliga ANSI | `false` |

**Cuidado com `-o` para arquivo:** `save_output()` monta o JSON como `{"url": target, **scan}` — ou seja, o dicionário completo do `target` (identidade, rede, TLS, DNS, HTTP, conteúdo) fica salvo sob a chave `"url"`, misturado com os campos do `scan` no nível raiz. Isso é diferente do formato que a API HTTP devolve (`{"scan": {...}, "target": {...}}`), então não assuma que o JSON salvo pelo CLI tem o mesmo shape do `AnalyzeResponse` da API — hoje eles divergem.

Não há CLI publicado para `scfs` ou `scqr` isoladamente (nenhum entry point em `pyproject.toml` além de `scurl` e `scamlens-api`); só existem como módulos internos.

## Análise de arquivos — scfs

A rota fica em `api/router/scfs/file.py`, com esquemas de entrada/saída na pasta `schema`, seguindo a organização de `scurl`.

```powershell
curl.exe -X POST http://localhost:5300/api/scfs/analyze/file -F "file=@C:/caminho/amostra.exe"
```

O campo multipart é `file`. O motor faz análise estática de PE, ELF, Mach-O e scripts suportados, sem executar o arquivo. A resposta segue o envelope `{scan, target}`; `scan.status` pode ser `ok`, `partial` ou `inconclusive`. Resultados inconclusivos mantêm score nulo.

Os limites vêm de `[scfs.scanner]` em `scamLens/config.toml`: `max_file_size_bytes` (padrão 50000000), `k`, `max_strings`, `score_model` e `disabled_rules`. A configuração é carregada e validada pelo `scamLens/__init__.py`; não há um arquivo `configuration.py` separado.

A rota usa a mesma autenticação opcional e as mesmas cotas por plano de `scurl`, com uso diário registrado no módulo `scfs`. A cota anônima por IP é compartilhada com os outros scans. Erros de upload/análise não consomem a cota.

Respostas: `400` para arquivo vazio/corrompido, `401` para cota anônima esgotada, `413` para tamanho excedido, `415` para formato não suportado, `422` para ausência de arquivo, `429` para cota diária/rate limit e `503` para scanner ocupado. Não é criado histórico de scans de arquivo nesta rota; o arquivo enviado não é persistido pela aplicação.


## Chat

A integração da branch `chat` expõe uma sala comum aos usuários autenticados. HTTP e WebSocket aceitam o cookie `access_token` ou o header `Authorization: Bearer <access_token>`. Tokens ausentes, inválidos, revogados ou de usuários inativos não autenticam a conexão; o WebSocket encerra com código 1008 quando a autenticação falha.

### Enviar uma mensagem

`POST /api/chat/messages`, com JSON:

```json
{
  "content": "Olá!",
  "sent_at": "2026-10-20T12:00:00-03:00"
}
```

`content` e `sent_at` são obrigatórios. O conteúdo é aparado e mensagens vazias ou acima do limite são rejeitadas com 422. O horário é normalizado para UTC; horários sem fuso são interpretados como UTC. A resposta 201 contém `id`, `name`, `avatar_url`, `content` e `sent_at`. Nome e avatar vêm do usuário autenticado.

Erros de validação retornam somente `loc`, `msg` e `type` em `detail`, sem copiar a entrada recusada nem o contexto do validador. Isso vale para toda a API. A seção `[validation]` limita a quantidade de erros (`max_errors = 10`), o comprimento de cada texto (`max_detail_length = 200`) e a profundidade da localização (`max_location_depth = 8`), mantendo a resposta pequena mesmo com entradas grandes. Esses limites controlam a resposta de erro; não limitam o tamanho do corpo HTTP recebido.

### Histórico

`GET /api/chat/messages?limit=50&before_id=123` retorna uma lista, da mensagem mais antiga para a mais nova dentro da página. `before_id` é opcional: use o ID da primeira mensagem da página recebida para buscar a página anterior. O cursor considera o horário e o ID da mensagem, inclusive quando mensagens foram enviadas com horários fora de ordem. O parâmetro `limit` deve estar entre 1 e o limite configurado; `before_id`, quando informado, deve ser positivo.

### Tempo real

Conecte a `ws://localhost:5300/api/chat/ws` em HTTP local ou use `wss://` quando a API estiver em HTTPS. Cookies Secure exigem conexão segura. A publicação é feita por POST; o WebSocket recebe eventos JSON com `type: "message"` e os mesmos campos da resposta de envio.

O broadcast ocorre após a gravação no banco e alcança os clientes conectados ao mesmo processo. Não há sincronização de eventos entre múltiplos workers nem salas privadas nesta integração. O histórico continua persistido em SQLite.

### Banco e configuração

O `init_db()` carrega `providers/database/schema/chat.sql` e cria `chat_messages` e seus índices sem apagar os dados existentes. A tabela armazena o usuário remetente, conteúdo, horário do cliente (`sent_at`) e horário de gravação (`created_at`). As conexões habilitam foreign keys; a relação com usuários declara `ON DELETE CASCADE`.

Em `scamLens/config.toml`:

```toml
[chat]
max_message_length = 2000
default_page_size = 50
max_page_size = 100
```

Reinicie a API após alterar a configuração ou integrar as novas rotas. A dependência `websockets` faz parte da instalação de runtime para que o Uvicorn disponibilize o transporte WebSocket.
