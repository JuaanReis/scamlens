# Arquitetura do scurl

O scurl é um motor heurístico modular para detecção de URLs maliciosas. A arquitetura separa coleta de dados, execução de heurísticas, resolução contextual, cálculo de score e formatação de resposta em estágios independentes. Esse design permite que o mesmo pipeline seja reutilizado tanto pela CLI quanto pela API REST sem duplicação de lógica.

---

## Estrutura de diretórios

```
scurl
├── assets        # Recursos visuais do projeto: logos, imagens e arquivos estáticos.
├── cli           # Interface de linha de comando: entrada de argumentos e saída formatada.
├── datasets      # Bases auxiliares usadas nas análises (keywords, marcas e wordlists).
├── docs          # Documentação técnica: arquitetura, heurísticas, score e instalação.
├── engine        # Núcleo do fluxo de execução: coleta, pipeline e montagem do resultado.
├── heuristics    # Regras de detecção de fraude/phishing divididas por categoria.
├── models        # Estruturas e modelos de dados compartilhados pelo sistema.
├── parsers       # Processamento e normalização de HTML, URLs e respostas externas.
├── scoring       # Cálculo de score, pesos e nível de confiança final.
├── scurl         
│   └── __init__.py
├── config.toml   # Arquivo de configuração do projeto.
├── CONTRIBUTING.md # Guia de contribuição e padrões de desenvolvimento.
└── README.md     # Visão geral, uso e apresentação do Scurl.
```

---

## Entrypoints

O `pyproject.toml` define dois scripts:

```
scurl      →  app.cli.main:main
scurl-api  →  app.api.server:run
```

Ambos executam o mesmo pipeline de análise — a diferença é apenas a camada de apresentação.

---

## Pipeline de análise

O fluxo principal vive em `core/engine/pipeline/` e é orquestrado por `core/engine/engine.py`. Os estágios são executados em sequência, passando um objeto `ScanContext` entre si.

```
run_engine(url)
      │
      ▼
validate_url        → valida schema, normaliza host, extrai estrutura
      │
      ▼
collect             → coleta dados externos (HTTP, DNS, SSL, RDAP, Safe Browsing)
      │
      ▼
execute             → executa todas as heurísticas em paralelo (ThreadPoolExecutor)
      │
      ▼
context_apply       → aplica dependências entre heurísticas (reduce / increase / skip)
      │
      ▼
score               → calcula score final (média ponderada + sigmoid)
      │
      ▼
response_builder    → monta ScanResult e TargetData para retorno
```

### validate_url

Valida o schema (`http`/`https`), normaliza o hostname, extrai subdomínios, TLD, path, query e fragment via `tldextract` e `urlparse`. Retorna um `ScanContext` populado com a estrutura da URL.

### collect

Faz todas as requisições externas **uma única vez** e injeta os dados no `ScanContext`. Inclui:

- Requisição HTTP completa (headers, redirect chain, body, timing)
- Resolução DNS (A, AAAA, MX, NS, TXT, SPF, DKIM, TTL)
- Inspeção de certificado TLS via `providers/ssl`
- Consulta RDAP via `providers/rdap`
- Consulta Google Safe Browsing via `providers/safebrowsing`
- Parsing do HTML via `selectolax` (centralizado — cada heurística lê a árvore já parseada)

A centralização da coleta evita que múltiplas heurísticas façam requisições redundantes ao mesmo alvo.

### execute

Executa todas as heurísticas registradas via `@register` em paralelo usando `ThreadPoolExecutor`. Cada heurística recebe o `ScanContext` como entrada e retorna um `ResultBase`. Heurísticas que retornam `normalized = None` são marcadas como não aplicáveis e excluídas do cálculo de score.

### context_apply

Segunda passagem sobre os resultados. Aplica o sistema de dependências definido em `core/scoring/dependencies.py`: para cada regra, verifica se outras regras disparam condições de `reduce`, `increase` ou `skip`. Quando `reduce` e `increase` conflitam na mesma regra, `reduce` vence. O resultado é um conjunto de scores ajustados ao contexto do alvo específico.

### score

Calcula o score final em dois passos:

1. **Média ponderada** dos `normalized` ajustados, usando os `weight` de cada heurística
2. **Transformação sigmoid** (k=5) que mapeia o resultado para `[0, 100]`

### response_builder

Monta dois objetos separados:

- **ScanResult** — score, risk_level, verdict, heurísticas triggeradas, insights, stats, metadados do scan
- **TargetData** — estrutura completa do alvo: identity, network, TLS, DNS, HTTP, content, domain

---

## Camada de providers

Os providers em `providers/` são responsáveis exclusivamente por I/O externo. Nenhuma lógica de scoring ou heurística vive aqui.

| Provider | Responsabilidade |
|---|---|
| `http` | Requisição HTTP, redirect chain, headers, body, timing |
| `dns` | Resolução DNS usando `dnspython` |
| `ssl` | Conexão TLS, extração de certificado, SANs, fingerprints |
| `rdap` | Consulta RDAP para dados de registro do domínio |
| `safebrowsing` | Consulta à Google Safe Browsing API v4 |
| `database` | SQLite: inicialização, connection pool, repository (list/get/save scans) |

---

## Camada de heurísticas

As heurísticas em `core/heuristics/` são funções puras registradas via decorator `@register`. Cada uma:

- recebe `structure: dict` (o `ScanContext` serializado)
- retorna `ResultBase(value, normalized, details)`
- não faz I/O externo
- não conhece outras heurísticas

A separação em categorias (`url/`, `html/`, `server/`) é organizacional — o pipeline não trata categorias diferentemente durante a execução.

---

## Camada matemática

`core/math/` contém funções utilitárias sem dependência de estado:

| Módulo | Função |
|---|---|
| `shannon_entropy` | Entropia de Shannon para detecção de strings aleatórias |
| `levenshtein` | Distância de edição para typosquatting |
| `jaccard_similarity` | Similaridade de conjuntos para comparação de domínios |
| `exponential_decay` | Curva de decaimento para domain age scoring |
| `value_normalizator` | `minmax`, `normalize_counter` — normalização de valores brutos |
| `sigmoid` | Transformação sigmoid ponderada usada no score final |
| `n_gram` | N-gramas para análise textual |
| `sequence_matcher` | Wrapper de SequenceMatcher para similaridade de strings |

---

## Modelos de dados

`core/models/` define os dataclasses que trafegam pelo pipeline:

| Modelo | Descrição |
|---|---|
| `ScanContext` | Objeto central — carrega todos os dados coletados e a estrutura da URL |
| `ResultBase` | Retorno de cada heurística: `value`, `normalized`, `details` |
| `ScanRule` | Metadados de uma regra: `name`, `category`, `severity` |
| `ScanResult` | Resultado final do scan para retorno ao cliente |
| `SubScore` | Sub-resultado interno das heurísticas compostas (dns_score, ssl_score) |
| `HttpResult` | Dados brutos da resposta HTTP |

---

## Sistema de cache

Ativado com `--cache` na CLI ou `use_cache: true` na API.

- Chave: `SHA-256(url_normalizada)`
- Storage: SQLite em `~/.scurl/scurl.db` (ou path via `SCURL_DB_PATH`)
- Hit: retorna resultado armazenado sem executar o pipeline
- Miss: executa o pipeline completo e persiste o resultado

No Vercel, o path deve ser configurado para `/tmp/scurl.db` via variável de ambiente — o filesystem é read-only fora de `/tmp` e os dados não persistem entre cold starts.

---

## Modelo de concorrência

| Componente | Modelo |
|---|---|
| Coleta de dados (`collect`) | Síncrono sequencial (cada provider faz I/O uma vez) |
| Execução de heurísticas (`execute`) | Paralelo via `ThreadPoolExecutor` |
| API REST | Assíncrono via FastAPI/uvicorn com semáforo de 20 scans simultâneos |
| CLI | Síncrono — o `run_engine` é chamado diretamente |

---

## Fluxo de dados resumido

```
URL (string)
  └─▶ validate_url  →  ScanContext (estrutura da URL)
        └─▶ collect  →  ScanContext (+ dados externos injetados)
              └─▶ execute  →  list[ResultBase] (uma por heurística)
                    └─▶ context_apply  →  list[ResultBase] (scores ajustados)
                          └─▶ score  →  float (0–100)
                                └─▶ response_builder  →  (ScanResult, TargetData)
```