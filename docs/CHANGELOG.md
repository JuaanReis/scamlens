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

## [3.2.7]

Alterações em relação à versão **2.0.5**, registrada no commit `0c80ac6`. A comparação inclui os arquivos novos da integração local.

### Adicionado

- Motor de arquivos `scfs` integrado na versão `1.1.0`, com coleta, extração de características, execução de regras, pontuação, classificação e retorno `(scan, target)`.
- Chat integrado a partir de `origin/chat` (`2b5ac6b`), com `GET /api/chat/messages`, `POST /api/chat/messages` e WebSocket `/api/chat/ws`, usando autenticação por cookie ou Bearer.
- Persistência de mensagens em `chat_messages`, com usuário, conteúdo, horário informado pelo cliente e horário de gravação, índices de consulta e remoção em cascata vinculada ao usuário. O esquema `chat.sql` é aplicado pelo `init_db` também em bancos existentes.
- Configuração `[chat]` para tamanho máximo de mensagem e paginação; normalização de horários para UTC e transmissão das mensagens persistidas para os clientes conectados ao processo.
- Parsers estáticos para PE32/PE32+, ELF32/ELF64, Mach-O32/Mach-O64 e Mach-O universal, além de scripts PowerShell, BAT, CMD, VBS, JavaScript, shell e Python. Scripts aceitam UTF-8 e UTF-16 com BOM; o conteúdo analisado não é executado.
- Coleta de arquivos com limite de bytes, exigência de arquivo regular, identificação de alteração durante a leitura, SHA-256, extração limitada de strings e informações estruturais do executável.
- Registro de 25 regras no `scfs`, cobrindo injeção de processo, acesso a credenciais, persistência, evasão de defesas, comandos destrutivos, download com execução, execução codificada, antianálise, literais codificados, memória gravável/executável, empacotamento, permissões do entrypoint, disfarce de nome e reputação externa.
- Regras de captura de teclado, tela e clipboard, instalação de serviços, manipulação de tokens, artefatos de ransomware, exfiltração de dados, uso suspeito de binários do sistema, resolução dinâmica de imports, executáveis embutidos e sobreposição de seções no `scfs`.
- Modelo `grouped` do `scfs`, com seleção das três famílias de evidências mais fortes, e opção `legacy` para média ponderada de todas as regras. A resposta informa grupos, contribuições, score bruto, regras avaliadas, indisponíveis, desabilitadas e com falha.
- Estados `ok`, `partial`, `inconclusive` e `error` no motor de arquivos. Resultados inconclusivos ou com erro mantêm score nulo e classificação desconhecida.
- Contrato opcional de provider de reputação para o `scfs`, consultado por SHA-256. Falhas do provider geram avisos sem transformar indisponibilidade em resultado seguro.
- Rota `POST /api/scfs/analyze/file`, organizada em `api/router/scfs/`, com upload multipart no campo `file`, esquemas Pydantic próprios e resposta `{scan, target}`.
- Autenticação opcional, cota anônima compartilhada por IP, uso diário autenticado identificado pelo módulo `scfs`, semáforo de concorrência, leitura limitada do upload e sanitização do nome de arquivo na nova rota.
- Respostas HTTP `400`, `401`, `413`, `415`, `422`, `429` e `503` para os erros de entrada, formato, tamanho, autenticação/cota, validação e ocupação do scanner de arquivos. Registro de requisições `/api/scfs` no middleware de logging.
- Entrada `python -m plugins.scfs`, opção `--json` e códigos de saída `0` para classificação segura, `1` para risco sinalizado, `2` para erro/resultado inconclusivo e `130` para interrupção.
- Indicadores editáveis em JSON, controles de calibração de engenharia e testes sintéticos de regressão para parsers, regras, pontuação, limites, providers, arquivos truncados e mutações de cabeçalhos do `scfs`.
- Seis regras no `scurl`: `brand_subdomain` (domínio usado como isca em subdomínio), `unicode_mixed_script` (mistura de alfabetos), `cleartext_transport` (HTTP), `credential_cleartext` (senha por HTTP), `credential_exfiltration` (coocorrência de credenciais, requisição e destino externo em script) e `misleading_link` (texto de link divergente do destino).
- Ativação da regra já existente `base64_segments` no agregador de heurísticas, totalizando 43 regras registradas no `scurl`.
- Resolução compartilhada de recursos HTML em `plugins/scurl/parsers/resources.py`, com suporte à URL final da página, ao elemento `<base>`, a caminhos relativos e à comparação de proprietário dos domínios.
- Provider compartilhado de estrutura de domínio em `providers/domain/`, com cache configurável, snapshot local da Public Suffix List e consideração de sufixos privados na comparação de proprietários.
- Modelo opcional `grouped` no `scurl`, com limites por regra e seleção de um sinal por grupo. Novo campo `scan.scoring` com `model`, `k` e `config_hash`, preservado pelo esquema da API.
- Sobrescrita parcial da configuração por meio de `SCAMLENS_CONFIG`, mantendo as opções padrão que não forem informadas no TOML adicional.
- Seções de configuração para domínio, SQLite, autenticação, uploads, cotas, TLS, regras, recursos HTML e política de pontuação. Inclusão dos parâmetros do `scfs` em `[scfs.scanner]`.

### Alterado

- Versão principal do pacote de `2.0.5` para `3.2.7`, motor `scurl` de `1.1.0` para `1.2.0` e motor `scfs` de `0.0.1` para `1.1.0`.
- Carga, mesclagem, validação e identificação da configuração de pontuação concentradas em `scamLens/__init__.py`, sem arquivo auxiliar `configuration.py`. Os valores ajustáveis permanecem em `scamLens/config.toml`.
- Validação antecipada de limites numéricos, tipos inteiros, valores finitos, faixas de classificação, modelos de pontuação, cotas e parâmetros bcrypt. Pesos, nomes e parâmetros das regras do `scurl` também são verificados; regras desabilitadas desconhecidas do `scfs` impedem o startup.
- Caminhos relativos de armazenamento, banco, logs, avatares e arquivos estáticos resolvidos a partir da raiz do projeto. Leitura do `.env` e do logo também passa a usar caminhos baseados no módulo.
- CLI e chamadas diretas de `run_engine` do `scurl` passam a ler `k`, timeout, threads e retries da configuração quando os argumentos não forem informados. Mantida a ordem dos argumentos posicionais; `score_model` foi acrescentado como argumento opcional somente por nome.
- Pesos e parâmetros nomeados das regras do `scurl`, faixas de classificação, grupos, limites de contribuição, domínios de recursos reconhecidos, timeout das regras e quantidade máxima de workers passam a ser definidos pelo TOML.
- Novas funções de heurísticas e utilitários adaptadas ao padrão dos módulos existentes, com tipagem, argumentos nomeados em `ResultBase` e documentação em português.
- Limite de tamanho de URL unificado entre API e motor por `scurl.security.max_url_length`, com padrão de 2048 caracteres, substituindo a restrição fixa de 100 caracteres da rota.
- Esquema de URL da API alterado de `HttpUrl` para `AnyHttpUrl`, permitindo aplicar o limite definido na configuração sem o limite implícito anterior do tipo.
- Análises de URL e QR passam a compartilhar o mesmo semáforo de concorrência. A rota de arquivos usa um semáforo próprio, com limite lido de `rate_limit.max_concurrent_scans`.
- Cache de URL passa a ter validade configurável, com padrão de 300 segundos, e exige versão do motor, modelo, `k` e identificação da configuração compatíveis. Registros antigos sem esses metadados são ignorados.
- Validação do destino passa a ocorrer antes da consulta ao cache. A CLI inicializa o banco quando o cache é solicitado; o motor deixa de persistir automaticamente scans executados sem cache, mantendo a persistência feita pelas rotas de URL/QR.
- Coleta do `scurl` passa a usar a estrutura da URL final para as análises de conteúdo, DNS, TLS e RDAP, preservando separadamente a URL original na resposta.
- Extração de domínio compartilhada entre parser de URL, comparação de recursos, diversidade de nameservers e provider RDAP, sem download implícito da lista de sufixos nesses fluxos. Uso de `top_domain_under_public_suffix` no lugar da propriedade descontinuada `registered_domain`.
- Campos `domain` e `netloc` incluídos na estrutura extraída da URL; reconhecimento de IP passa a usar `ipaddress`, incluindo IPv6.
- Análise de scripts externos passa a usar somente os dados já coletados e as listas de domínios/categorias da configuração.
- Limites de avatar, QR em bytes, QR em pixels, nome de usuário, senha, custo bcrypt, timeout SQLite, timeout TLS, cotas anônimas e cotas por plano passam a ser configuráveis. Planos usam `-1` para indicar ausência de limite.
- Duração do refresh token sem a opção `remember` passa a ser definida por `cookies.session_ttl_days`.
- Importação de CairoSVG adiada até uma entrada SVG ser processada, permitindo usar URL e imagens bitmap sem carregar a biblioteca nativa Cairo.
- `scimg` passa a preencher conteúdo, nome, tamanho e SHA-256 no contexto. Sua CLI retorna JSON com `status: validated` e `analysis_available: false`, deixando explícita a ausência de análise de fraude nesse módulo.
- README, documentação de uso e guia de integração do `scurl` atualizados com a rota de arquivos, os contratos efetivamente implementados e as instruções de configuração.

### Corrigido

- Logout passa a invalidar access tokens, além de refresh tokens, inclusive quando o access token é enviado por `Authorization: Bearer`.
- WebSocket do chat passa a exigir autenticação antes de aceitar a conexão, em alinhamento com as rotas HTTP.
- Respostas 422 de validação da API deixam de devolver `input` e `ctx`, evitando refletir mensagens grandes do chat, senhas e outros dados recusados. Permanecem `loc`, `msg` e `type`, com limites de quantidade, comprimento e profundidade definidos em `[validation]`.
- Paginação do chat passa a usar a combinação de horário e ID do cursor, evitando repetições ou omissões quando os horários dos clientes não seguem a ordem de inserção. Limites e IDs de paginação inválidos são rejeitados.
- Conexões SQLite passam a ativar `foreign_keys`, tornando efetiva a integridade referencial declarada nos schemas, inclusive a remoção em cascata das mensagens do chat.
- Decodificação JWT passa a exigir `sub`, `exp`, `iat`, `type` e `jti`, validar o identificador de usuário positivo e verificar revogação para os dois tipos de token.
- Cadastro duplicado passa a fazer rollback da transação SQLite, evitando manter o banco bloqueado após falha por e-mail existente.
- Senhas vazias ou maiores que o limite de bytes UTF-8 passam a ser rejeitadas antes do bcrypt, respeitando o teto de 72 bytes e a compatibilidade com bcrypt 4 e 5. Nome de usuário também passa a ter tamanho validado.
- Cota anônima passa a considerar a data do contador e reiniciar diariamente, em vez de manter o total acumulado indefinidamente.
- Upload de avatar passa a retornar `/storage/avatars/<arquivo>`, com montagem explícita do diretório configurado, em vez de expor um caminho local que não podia ser acessado pela API.
- Rotas de URL e QR deixam de capturar qualquer exceção como ausência de autenticação; o fallback anônimo passa a tratar apenas `HTTPException`.
- Hash do cache deixa de tratar domínio principal e `www`, credenciais na URL ou caminhos com/sem barra final como destinos equivalentes. Fragmentos também permanecem na identificação do alvo.
- Redirecionamentos HTTP passam a resolver destinos relativos e `//host` com `urljoin`, detectar loops, validar cada destino e preservar a quantidade de saltos e a cadeia de respostas.
- Acesso a endereços multicast e reservados passa a ser bloqueado juntamente com os demais endereços restritos. Portas e autoridades malformadas passam a produzir erro de validação controlado.
- Verificação de `form action` passa a analisar o destino real do formulário, em vez de comparar apenas informações da própria página.
- Favicon relativo deixa de ser classificado como externo; imagens, formulários, scripts e verificações de integridade usam a resolução comum de recursos e a comparação de domínio.
- Reconhecimento de domínios de scripts confiáveis passa a exigir igualdade ou limite de subdomínio, evitando aceitar nomes como `evilgoogle.com` por coincidência de sufixo.
- Detecção de redirecionamento JavaScript passa a reconhecer atribuições a `location`/`location.href` e chamadas a `location.replace`/`location.assign`. Meta refresh preserva a capitalização do caminho de destino.
- Heurística de IP passa a considerar somente o hostname, incluindo IPv6, evitando sinalizar números de IP presentes apenas no caminho ou na query. A heurística de `@` passa a considerar somente a autoridade da URL.
- Recalcular a pontuação em um mesmo contexto passa a limpar scores, pesos e heurísticas anteriores. A sigmoide do `scurl` foi reescrita de forma numericamente estável para evitar overflow com valores altos de `k`.
- Upload QR passa a ter leitura limitada antes de chamar o motor. O decoder também verifica tamanho de arquivos/bytes e quantidade de pixels das imagens.
- Entradas QR inválidas, arquivos ausentes/inacessíveis, falhas de conversão SVG e ausência de Cairo passam a retornar erros controlados. Os tipos de erro do decoder são preservados pelo pipeline de QR.
- Retry HTTP passa a ocorrer também para respostas `429`, `500`, `502`, `503` e `504` retornadas normalmente pelo cliente, sem depender de uma exceção HTTP.
- Leitura numérica de `Retry-After` passa a ignorar capitalização do header, usar fallback para valores inválidos/não finitos e limitar a espera por `http.max_retry_delay`.
- Coleta TLS passa a manter a validação da cadeia e do hostname do contexto padrão, respeitar a porta do destino e o timeout configurado e deixar de abrir conexão TLS para alvos HTTP.
- CLI `scurl` passa a rejeitar ausência de alvo e parâmetros não positivos, emitir JSON UTF-8 em `-o -` e devolver `2` em erros e `130` em interrupções. Execuções concluídas mantêm saída `0`.
- CLIs de `scfs` e `scimg` passam a rejeitar ausência de arquivo. Contexto e construtor do `scimg` foram alinhados; seu hash passa a ser calculado sobre o conteúdo, em vez do nome do arquivo.
- Schemas SQL passam a ser lidos explicitamente em UTF-8; a conexão SQLite passa a usar o timeout da configuração.
- Formatação do cabeçalho de logs ajustada para não depender de f-strings com reutilização de aspas introduzida em versões mais recentes do Python. `datetime.UTC` substituído por `timezone.utc` nos metadados do `scurl`.
- Tempo de bootstrap calculado pela diferença entre as leituras de `perf_counter()`, em segundos, em vez de exibir a leitura bruta do cronômetro. Removida a divisão indevida por 1000 no logging, com tratamento de valor ausente.

### Removido

- Consultas de ASN e WHOIS feitas dentro da heurística de scripts externos, junto com a classificação automática de confiança baseada em ASN ou infraestrutura compartilhada.
- Requisição `HEAD` a URLs OCSP extraídas de certificados e uso de channel binding como suposta prova de OCSP stapling. Os campos correspondentes passam a retornar `None` quando não verificados.
- Regra ampla `scfs/` do `.gitignore`, que ocultava tanto os novos arquivos do motor quanto a pasta de rotas da API. Acrescentada regra para o cache do pytest.

### Compatibilidade e limites

- Dependências anteriores de runtime foram mantidas e `websockets>=13.0` foi acrescentado para o transporte WebSocket do chat no Uvicorn. O extra `test` é opcional.
- O chat é uma sala comum aos usuários autenticados. A transmissão em tempo real usa conexões em memória por processo; não há sincronização de eventos entre múltiplos workers.
- O `scurl` mantém `legacy` como modelo padrão; `grouped` é uma opção. O `scfs` usa `grouped` por padrão e também aceita `legacy`. As pontuações podem mudar com as novas regras e políticas de configuração; não representam probabilidades calibradas.
- A rota do `scfs` não cria histórico de scans de arquivo e não persiste o arquivo enviado. Requisições com erro de análise não consomem cota; resultados inconclusivos continuam identificados como tal.
- O `scimg` continua restrito à validação de entrada e metadados/hash, sem detector de fraude nem nova rota HTTP.
- SVG continua exigindo a biblioteca nativa Cairo. A ausência dessa dependência é tratada sem impedir análises de URL ou QR em formatos bitmap.
- As mudanças de validação e redirecionamento não estabelecem garantia de proteção completa contra DNS rebinding. Não foi acrescentado limite de corpo HTTP nem validação OCSP conclusiva.
