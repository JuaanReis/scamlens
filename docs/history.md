# Histórico de análises e logs

## Persistência

As rotas de análise SCFS e SCPIX gravam cada resultado concluído (`ok`, `partial` ou `inconclusive`) na tabela `module_scans`. A mesma entrada analisada duas vezes produz dois `scan_id` distintos. Entradas rejeitadas não geram resultado de histórico, mas a requisição aparece nos logs com o status HTTP.

O registro contém módulo, identificador, hash SHA-256 do alvo, nome, status, score, classificação, tempo, data, proprietário e o JSON estruturado devolvido ao cliente. Não guarda arquivo, script completo, payload Pix bruto, chave completa ou token de URL de cobrança. SCFS e SCPIX via engine/CLI continuam sem persistência automática.

URL e QR preservam a tabela `scans` existente, com uma linha por hash de URL e atualização da análise anterior. Os resultados de QR compartilham o módulo `scurl` no histórico. SCIMG ainda não produz análises e não participa do histórico.

`init_db()` cria a tabela e os índices novos e acrescenta `request_logs.module` de forma idempotente. Logs anteriores são classificados pelo endpoint. Resultados SCFS/SCPIX anteriores à integração não podem ser recuperados porque nunca foram salvos.

## Consultar resultados

Autenticação: cookie `access_token` ou `Authorization: Bearer <token>`.

| Método | Rota | Acesso |
|---|---|---|
| GET | `/api/scfs/scans` | Usuário: seus arquivos; admin: todos os arquivos |
| GET | `/api/scfs/scans/{scan_id}` | Proprietário ou admin |
| GET | `/api/scpix/scans` | Usuário: seus Pix; admin: todos os Pix |
| GET | `/api/scpix/scans/{scan_id}` | Proprietário ou admin |
| GET | `/api/user/scans` | Histórico do usuário atual em todos os módulos |
| GET | `/api/admin/scans` | Histórico de todos os usuários e anônimos, somente admin |

As listas aceitam `limit` (1–200, padrão 50) e `offset` (a partir de 0), ordenam do mais recente e retornam `{status, total, limit, offset, scans}`. `total` é a contagem completa após os filtros, não apenas o tamanho da página. O detalhe retorna o mesmo `{scan, target}` da análise.

As listas de SCFS/SCPIX também aceitam `target_hash` (64 caracteres) para procurar análises repetidas. `/api/user/scans` aceita `module=scurl|scfs|scpix`. `/api/admin/scans` aceita os mesmos módulos e `user_id`. Um identificador inexistente ou pertencente a outro usuário retorna HTTP 404. Históricos novos sem autenticação retornam HTTP 401. Resultados anônimos só são consultáveis pelo admin.

Os históricos públicos de URL/QR em `/api/scurl/scans` preservam seu comportamento anterior. Avatares continuam acessíveis em `/storage/avatars/`; a pasta inteira de armazenamento não é servida, para que banco e logs não sejam baixados sem autenticação.

## Logs e métricas de administração

`GET /api/admin/request-logs` mantém o retorno em lista e acrescenta o campo `module`. Filtros opcionais:

- `module`: `scurl`, `scqr`, `scfs`, `scpix` ou `chat`;
- `scan_id`: vínculo entre requisição e resultado;
- `user_id`: proprietário autenticado;
- `status_code`: status HTTP, incluindo entradas inválidas e erros;
- `limit`: 1–500, padrão 200; `offset`: a partir de 0.

Exemplos:

```text
GET /api/admin/request-logs?module=scpix&status_code=200
GET /api/admin/request-logs?module=scfs&scan_id=<scan_id>
GET /api/admin/scans?module=scpix&user_id=2&limit=20
GET /api/user/scans?module=scfs
```

`GET /api/admin/logs` continua listando arquivos de log; `/api/admin/logs/{filename}` permite ler as linhas finais. Requisições Pix também aparecem nesses arquivos. Leituras administrativas são registradas em `admin_audit_log`.

As métricas globais e a atividade em `/api/user/me` somam os resultados de todos os módulos persistidos. O tempo médio do usuário é calculado a partir dos logs de requisições de análise bem-sucedidas, quando disponíveis. Cotas não são consumidas quando o resultado SCFS/SCPIX não consegue ser salvo; a API responde HTTP 503 nesses casos.
