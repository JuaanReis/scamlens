# scfs 1.1.0

Motor heurístico de análise estática de executáveis para uso independente ou como plugin do ScamLens. Python 3.11+, biblioteca padrão, sem dependências de runtime. Não executa, importa ou descompacta o arquivo analisado.

## Uso rápido

A pasta entregue é o próprio pacote Python, com `__init__.py` na raiz. A partir do diretório **pai** de `scfs/`:

```bash
python -m scfs arquivo.exe
python -m scfs arquivo.dll arquivo.elf script.ps1 --json
python -m scfs
python -m scfs --list-rules
python -m scfs arquivo.exe --k 5 --max-mib 64
python -m scfs arquivo.exe --score-model legacy
python -m scfs.calibration
python -m scfs arquivo.exe --disable-rule anti_analysis
python -m unittest scfs.tests.test_engine scfs.tests.test_v110 -v
```

Sem argumentos, solicita o caminho interativamente. A CLI não percorre diretórios automaticamente. `--json` escreve um objeto `{scan, target}`, ou uma lista para múltiplos caminhos. Códigos de saída: **0** classificação safe; **1** suspicious/dangerous/malicious; **2** erro ou resultado inconclusivo. `safe` significa poucos indicadores encontrados, não certificação de segurança. Consulte sempre `status` e `warnings`, inclusive em saída 0.

Instalação opcional, de dentro da pasta:

```bash
python -m pip install .
scfs arquivo.exe --json
```

O `pyproject.toml` instala esta própria pasta como pacote `scfs`; não existe outra pasta `scfs/` aninhada. Não é necessário instalar para integrar ao ScamLens.

## Integração

Copie **esta pasta inteira** para `plugins/scfs/`, incluindo `datasets/indicators.json`.

```python
from plugins.scfs import run_engine, Settings

scan, target = run_engine("arquivo.exe")
# Mesmo padrão de retorno do scurl; quem integra decide o envelope HTTP.
response = {"scan": scan, "target": target}

scan, target = run_engine(
    uploaded_bytes,
    name="arquivo.exe",  # necessário para reconhecer scripts sem shebang
    settings=Settings(k=5.0, max_file_bytes=32 * 1024 * 1024),
)
```

Não há import obrigatório de `scamLens`, banco, configurações globais, cache, FastAPI, rede ou persistência automática. O host deve passar a configuração explicitamente, por exemplo `Settings(**config["scfs"])`, usando somente as chaves documentadas em `config.py`. Isso evita dependência circular e permite CLI independente. O scanner é síncrono e faz trabalho de CPU; uma rota async deve delegá-lo a um executor/processo apropriado ao host. `threads=1` nos metadados informa o comportamento real.

## Formatos

| Família | Cobertura |
|---|---|
| PE32/PE32+ | EXE, DLL, SYS, SCR, CPL e outros contêineres PE válidos; cabeçalhos, seções, permissões, entrypoint e importações por nome |
| ELF32/ELF64 | Little/big endian; ET_EXEC/ET_DYN, segmentos LOAD e permissões; executáveis, PIE e bibliotecas |
| Mach-O32/64 | Little/big endian; imagens, dylibs, bundles; comandos de segmento e bibliotecas carregadas |
| Mach-O universal | FAT32/FAT64 e suas fatias Mach-O |
| Scripts | `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.sh`, `.py`, ou shebang; UTF-8/UTF-8 BOM/UTF-16 BOM |

Binários são reconhecidos por assinatura e estrutura, não pela extensão. Objetos ELF relocáveis, DOS MZ puro, MSI, APK, JAR, bytecode, atalhos LNK e arquivos compactados não são suportados. Um MZ sem cabeçalho PE válido retorna erro. Esses parsers são deliberadamente limitados e rejeitam tabelas excessivas; não implementam todas as extensões dos formatos. Não há desassemblagem, reconstrução de fluxo, análise de macros ou de código .NET IL.

## Arquitetura

```text
scfs/
  __init__.py                 API pública e versão
  __main__.py                 entrada python -m
  config.py                   Settings imutável
  cli/                        argumentos, interação e apresentação
  engine/main.py              orquestração
  engine/pipeline/             coleta, execução, pontuação, resposta
  engine/analysis/             classificação separada
  models/scan_context.py       TargetData, ScanMeta, ScanContext
  calibration.py              controles, candidatos de k e manifesto rotulado
  parsers/                    PE, ELF, Mach-O, scripts, strings
  heuristics/registry.py       RuleEntry, register, get_rules
  heuristics/content.py       indicadores e combinações
  heuristics/structure.py     estrutura e reputação
  scoring/                    média ponderada e sigmoide
  providers/                  contrato para dados externos
  datasets/indicators.json     indicadores editáveis
  tests/                      fixtures inertes e regressões
  docs/                       pontuação e limites
```

Fluxo: snapshot limitado → identificação/parse → características compartilhadas → provider opcional → regras → agregação por famílias → média ponderada → sigmoide → classificação → `(scan, target)`. Nenhum alvo é executado. As regras usam dados do contexto; não fazem chamadas externas.

## Providers

Por padrão, o scanner é offline. Para usar dados externos, implemente um adaptador no **`providers` do host**, conforme o contrato de `scfs/providers/reputation.py`, e passe sua instância:

```python
class MeuProvider:
    def lookup(self, sha256):
        # Aqui seu providers consulta um serviço, com timeout e retries próprios.
        # Retorne None para hash desconhecido. Não confunda indisponibilidade com zero detecções.
        return {"malicious": 3, "total": 20, "source": "meu-servico"}

scan, target = run_engine("arquivo.exe", reputation_provider=MeuProvider())
```

`lookup` recebe somente SHA-256, uma vez por análise. O motor não transmite arquivo nem escolhe serviço, chave ou cliente HTTP. Timeout/credenciais/retries são responsabilidade do provider; ele não deve bloquear indefinidamente. Erros e respostas inválidas produzem aviso e score `None` nessa regra, sem zerar o risco. A reputação participa da mesma média; não é um bloqueio absoluto. Para política de bloqueio por blacklist, o host deve consultar também `target.reputation`.

## Regras e resultados

25 regras registradas. As 14 anteriores incluem: injeção de processo, credenciais, persistência, evasão de defesas, comandos destrutivos, rede + execução, codificação + execução, antianálise, literal codificado longo, memória W+X, empacotamento/entropia, permissões do entrypoint, nome disfarçado e reputação externa. As 11 novas são captura de teclado, tela e clipboard, serviços, tokens, artefatos de ransomware, exfiltração, LOLBins, resolução dinâmica de imports, PE embutido e sobreposição de seções. [Critérios e pesos de todas as regras](docs/heuristics.md). `--list-rules` exibe os IDs.

Cada regra retorna score **0..1**, mensagem e evidências. `None` indica regra não aplicável/indisponível e fica fora da média; `disabled` e `error` também ficam fora. `score=0` indica regra avaliada sem indicador. Falhas de regras geram `partial`; zero regras avaliadas produz `inconclusive`, score nulo e verdict unknown. Erro de leitura/parse produz `error`, score nulo e target vazio. `Settings` inválido e ID de regra desconhecido levantam `ValueError`, pois são erros de integração.

`scan.result` usa os mesmos nomes e faixas do scurl. `scan.scoring` expõe média bruta, método, k, famílias e contribuições selecionadas. O padrão é `grouped`: até três famílias com pesos fixos; `Settings(score_model="legacy")` conserva a média de todas as regras atuais. Essa mudança evita diluição por regras neutras; ela muda as pontuações da versão 1.0. `calibrated=false` e `score_is_probability=false` registram explicitamente que não existe validação contra corpus real de malware nesta entrega; há controles sintéticos e um pequeno corpus de binários instalados presumidos legítimos. As informações de estrutura ficam em `target.executable`; texto completo do script e lista de strings não são devolvidos.

Para adicionar regra, use `@register(...)`, retorne `(score, mensagem, evidencias)` e importe o módulo em `heuristics/__init__.py`. Indicadores ficam no JSON; pesos e combinações ficam no código para permitir revisão explícita.

Leia [pontuação e calibração](docs/scoring.md), [heurísticas](docs/heuristics.md) e [limites e validação](docs/limitations.md). O relatório reproduzível está em `docs/calibration-report.json`.
