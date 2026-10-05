# Contribuindo para o ScamLens

Obrigado por considerar contribuir. Este documento descreve o ambiente de desenvolvimento, a estrutura real do projeto, padrões de código e o fluxo de PR — tudo conferido contra o estado atual do repositório em `main`.

---

## Índice

- [Ambiente de desenvolvimento](#ambiente-de-desenvolvimento)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Padrões de código](#padrões-de-código)
- [Commits](#commits)
- [Pull Requests](#pull-requests)
- [Testes](#testes)
- [Reportando bugs](#reportando-bugs)
- [Segurança](#segurança)
- [Checklist antes do PR](#checklist-antes-do-pr)
- [Licença](#licença)

---

## Ambiente de desenvolvimento

Clone o repositório:

```bash
git clone https://github.com/JuaanReis/scamlens.git
cd scamlens
```

Crie e ative um ambiente virtual:

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows
```

Instale em modo de desenvolvimento:

```bash
pip install -e .
```

### Variáveis de ambiente obrigatórias

`scamLens/__init__.py::get_settings()` lê estas do ambiente (ou de um `.env` na raiz, via `load_dotenv()`) — sem elas a API não sobe:

```bash
EMAIL_ADMIN=seu_admin@exemplo.com
PASSWORD_ADMIN=uma_senha_de_teste
JWT_SECRET=qualquer_string_longa_para_dev
GOOGLE_SAFE_BROWSING_KEY=sua_chave_de_teste
```

`.env` já está no `.gitignore` — nunca commite um `.env` real com chaves de verdade.

### Subindo a API localmente

```bash
scamlens-api
# ou, sem instalar o entry point:
uvicorn api.server:app --reload --port 5300
```

Isso cria automaticamente a conta admin (`ensure_admin_exists()`, a partir de `EMAIL_ADMIN`/`PASSWORD_ADMIN`) e inicializa o banco SQLite local no primeiro start. Para exercitar o CLI do motor de URL sem subir a API:

```bash
scurl https://exemplo.com -v
```

---

## Estrutura do projeto

Estrutura real (não a antiga descrita no `CONTRIBUTING.md` do `scurl`):

```
scamlens/
├── api/
│   ├── router/            # handlers de rota (auth, users, admin, system, scurl/*)
│   ├── middleware/         # auth.py, logging.py
│   └── server.py           # monta a app FastAPI, lifespan, inclui routers
├── plugins/
│   ├── math/                # utilitários compartilhados
│   ├── scfs/                 # motor de scan de arquivos (sem rota na API e sem CLI publicado ainda)
│   └── scurl/                 # motor de análise de URL
│       ├── engine/            # pipeline: validate_url → collect → target_structure → context_apply → execute → score → response_builder
│       ├── heuristics/         # heurísticas com @register, por categoria (url, html, server)
│       ├── cli/                 # comando `scurl`
│       └── vendor/scqr/          # decoder de QR code (interno, não é plugin irmão)
├── providers/               # I/O externo: http, dns, rdap, ssl, safebrowsing, database
├── docs/                     # architecture.md, usage.md
└── scamLens/
    └── config.toml            # config runtime da API (server, cors, cache, rate_limit, cookies)
```

Se você for adicionar um novo motor/plugin, siga o padrão de `plugins/scurl`: pipeline em estágios isolados dentro de `engine/`, heurísticas registradas via decorador, schema Pydantic próprio em `api/router/<plugin>/schema/`.

---

## Padrões de código

- Python 3.10+, tipagem explícita sempre que possível.
- Funções pequenas, uma responsabilidade por estágio de pipeline.
- Novas heurísticas: usar o decorador `@register`, isoladas e sem dependência entre si.
- Dependências declarativas de scoring seguem o formato `{op, val}` (fator multiplicativo) — não hardcode combinações de heurísticas em `if`/`else` soltos.
- Respostas de erro devem seguir o shape já usado em toda a API: `{status, meta: {version, ...}, error: {type, message}}` (ver `api/router/scurl/schema/map_error.py`). Não invente um shape de erro novo por endpoint.
- Evite listas fixas de comparação para detecção (ex.: domínios conhecidos, padrões de phishing) quando o dado tende a crescer ou mudar — prefira heurísticas que escalem (hashing, scoring, listas externas atualizáveis) em vez de listas hardcoded que ficam obsoletas.
- Nomes de tabela no banco são minúsculos e no plural quando fizer sentido (`plans`, `users`, `scans`, `revoked_tokens`) — siga essa convenção em vez de `UPPER_CASE`.

---

## Commits

Convenção usada no projeto (`feat`, `fix`, `refactor`, `docs`, etc.):

```text
feat: adiciona heurística para URLs encurtadas
fix: corrige cálculo de score SSL
refactor: simplifica pipeline de execução
docs: atualiza documentação da API
```

---

## Pull Requests

1. Crie uma branch focada em uma única mudança: `git checkout -b feat/nome-da-feature`
2. Descreva o problema resolvido e, se mudar comportamento de rota/schema, atualize `docs/architecture.md` e `docs/usage.md` no mesmo PR — não deixe a documentação desalinhar de novo.
3. Se a mudança afetar autenticação, quotas ou schema do banco, inclua um exemplo de request/response antes e depois.
4. Rode a API localmente e teste manualmente o(s) endpoint(s) afetado(s) — ver seção de testes abaixo.

---

## Testes

**Hoje não existe suíte de testes automatizados no repositório** — não há diretório `tests/`, nem `pytest.ini`/config de lint. Validação é manual (rodar a API local e testar via `curl`, conforme `docs/usage.md`). Se você for a primeira pessoa a adicionar testes:
- `pytest` é a escolha natural dado que o projeto já é 100% Python/FastAPI.
- Priorize cobrir `api/router/auth.py` (fluxo de token/revogação) e `plugins/scurl/engine/pipeline/` (estágios do pipeline), que são as partes com mais lógica de negócio e mais fácil de quebrar silenciosamente.
- Adicione a suíte ao `pyproject.toml` e documente o comando de execução aqui assim que existir.

---

## Reportando bugs

Ao abrir uma issue, inclua:

- versão do pacote (`pyproject.toml` → `version`)
- endpoint ou comando CLI usado, com o corpo da requisição (sem dados sensíveis)
- comportamento esperado vs. observado
- traceback completo, se houver
- se envolver autenticação: se o teste foi via cookie ou via `Authorization: Bearer`

---

## Segurança

Nunca commite:

- `.env` com chaves reais (`JWT_SECRET`, `GOOGLE_SAFE_BROWSING_KEY`, `PASSWORD_ADMIN`)
- arquivos `.db` reais (já cobertos pelo `.gitignore`, mas confira antes de forçar um `git add`)
- tokens de sessão capturados durante testes manuais

Se encontrar uma vulnerabilidade (ex.: bypass de auth, path traversal, SQL injection), não abra uma issue pública — reporte diretamente ao mantenedor.

---

## Checklist antes do PR

- [ ] testado manualmente localmente (não há CI/testes automatizados ainda)
- [ ] [docs/architecture.md](./ARCHITECTURE.md) e [docs/usage.md](./USAGE.md) atualizados se o comportamento de rota/schema/banco mudou
- [ ] sem imports não utilizados
- [ ] sem código comentado desnecessário
- [ ] sem `.env`, chaves ou tokens no diff
- [ ] sem quebra de compatibilidade não documentada (ex.: mudar path de rota sem atualizar os dois docs acima)

---

## Licença

Ao contribuir, você concorda que seu código será distribuído sob a licença [MIT](./LICENSE.md).