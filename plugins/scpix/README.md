# SCPIX — Heuristic Pix / BR Code Scanner

Módulo offline de avaliação **técnica e contextual** de payloads Pix copia e cola. Segue a arquitetura de `plugins/scfs`/`plugins/scurl`: `models`, `parsers`, `heuristics` (registry), `engine/pipeline`, `cli` e roteador FastAPI. Usa somente biblioteca padrão para o motor; a API reutiliza os providers externos **já presentes no projeto** para cotas de usuários e anônimos. Não depende de SCURL, SCQR, SCFS, NumPy, LLM ou TOML do módulo.

## Instalação

Copie as pastas `plugins/scpix/` e `api/router/scpix/` para a raiz do ScamLens. Execute **uma vez** na raiz:

```bash
python -m plugins.scpix.install_api
```

Esse comando só acrescenta import e `include_router` ao `api/server.py` original; não altera as demais rotas. É idempotente e aborta quando as âncoras esperadas não existem. Requer Python 3.11+ e as dependências FastAPI/Pydantic já existentes no ScamLens para a API.

## Engine e CLI

```python
from plugins.scpix import run_engine, Settings

scan, target = run_engine("000201...6304ABCD")
scan, target = run_engine(payload, expected={
    "merchant_name": "LOJA EXEMPLO",
    "amount": "35.90",
    "location_host": "pix.exemplo.com.br",
})
scan, target = run_engine(payload, settings=Settings(disabled_rules=("weak_location_token",)))
```

```bash
python -m plugins.scpix --payload '000201...6304ABCD' --json
python -m plugins.scpix --file cobranca.txt --json
python -m plugins.scpix --file cobranca.txt --expected-name 'LOJA EXEMPLO' --expected-amount 35.90
```

O parâmetro `source` aceita `str` (payload literal), `bytes` ou `pathlib.Path` (arquivo). **Não** tenta adivinhar se uma string é caminho. Código de saída CLI: `0` sem anomalias; `1` anomalias detectadas; `2` erro ou avaliação inconclusiva; `130` interrompido.

## API

`POST /api/scpix/analyze/pix` com corpo:

```json
{
  "payload": "000201...6304ABCD",
  "expected": {"merchant_name": "LOJA EXEMPLO", "amount": "35.90"}
}
```

Recebe a mesma tupla de retorno dos outros módulos: `{"scan": {...}, "target": {...}}`. Aplica semáforo de concorrência, limites diários e cotas de usuário/anônimo via os providers do projeto. `scan.status`: `ok`, `partial`, `inconclusive` ou `error`. Links dinâmicos **não** são buscados automaticamente.

## Regras e limites

- **41 heurísticas** em seis categorias: `integrity`, `structure`, `account`, `transaction`, `location`, `context`.
- CRC-16/CCITT-FALSE (0x1021, inicial 0xFFFF), TLV com detecção de duplicados/truncamentos, payload Pix em 26–51, suporte a 80–99 (recorrência), txid e formato de valores.
- Identifica tipos de chave sem consultar o DICT; faz checksum para CPF e CNPJ **numéricos**, e valida formato de CNPJ alfanumérico.
- Analisa estrutura de hostname, HTTPS, porta, credenciais, IPs/endereços não públicos, presença de query/fragmento, comprimento e tokens de locations.
- Contexto `expected`: `merchant_name`, `key`, `amount`, `txid`, `location_host` (todos opcionais). Sempre envie referências provenientes de fontes independentes da própria cobrança.
- Score `0–100` de **anomalia técnica/contextual**, modelo heurístico grouped-top3, com piso para violações críticas. Não é probabilidade de fraude, não foi calibrado por corpus e não prova legitimidade do recebedor. Um Pix bem formado pode ser fraudulento.
- Dados sensíveis: não retorna payload integral, chave Pix completa ou token de URL dinâmica. Expõe hash SHA-256 e chave mascarada; se usar logs, **não registre** requests com payloads brutos.
- QR Codes com cobrança dinâmica, composta ou recorrência: valida somente o BR Code local, **não** resolve JSON de cobrança, verifica PSP, obtém recebedor real nem valida titularidade da chave. Por isso usa status `partial` e aviso.

## Como adicionar uma regra

Crie uma função em arquivo sob `heuristics/` e use `@register(name, category, severity, weight, tags)`. A função recebe `ScanContext` e retorna `(score: float | None, message: str, evidence: list[str])`. `None` indica não aplicável. Importe o arquivo em `heuristics/__init__.py` para registrá-la.

## Referências normativas

- Banco Central do Brasil — Manual de Padrões para Iniciação do Pix v2.10.0 (capítulos 2.5–2.8): https://www.bcb.gov.br/content/estabilidadefinanceira/pix/Regulamento_Pix/II_ManualdePadroesparaIniciacaodoPix.pdf
- Banco Central do Brasil — Manual BR Code v2.0.1: https://www.bcb.gov.br/content/estabilidadefinanceira/spb_docs/ManualBRCode.pdf

## Notas operacionais

O SCPIX não inicia pagamento, não consulta dados pessoais do recebedor e não acessa os URLs do QR Code; nenhum PSP pode ser considerado autorizado só pela aparência do domínio. O servidor FastAPI não recebe automaticamente um módulo novo: execute `install_api` para registrar a rota. O módulo não contém arquivos de teste, conforme a restrição do projeto; execute as verificações funcionais antes de colocar em produção.
