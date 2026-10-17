# Pontuação — scfs 1.1.0

## Modelo padrão: grouped-top3-v1

A versão 1.0 diluía um sinal forte quando muitas outras regras retornavam zero. A versão 1.1 conserva as primitivas de **média ponderada + sigmoide**, mas altera a agregação: usa até três famílias de evidência, com orçamento fixo, em vez de dividir pelos pesos de todas as regras.

1. Para cada regra avaliada: `força = score * min(peso / 3, 1)`.
2. Para cada família: conservar a maior força, sem somar regras correlacionadas.
3. Ordenar as famílias e selecionar as três maiores forças positivas: `a, b, c`.
4. Completar os três slots com zero quando faltar evidência; esses zeros expressam falta de suporte, não prova de segurança.
5. Calcular `x = (3*a + 2*b + c) / 6`.
6. Aplicar `score = 100 / (1 + exp(-k * (x - 0.5)))`.

Exemplo: indicador destrutivo isolado tem score 0,7 e peso 3. Sua força é 0,7; x = (3*0,7)/6 = 0,35. Com k=5, o resultado é **32,08**, classificado como suspicious/moderate. Acrescentar cem regras neutras não diminui esse resultado. Acrescentar outra regra de mesma família com força menor também não o aumenta. Acrescentar evidência de outra família pode aumentá-lo.

Se todas as regras estiverem indisponíveis/desabilitadas, não existem slots avaliáveis: score nulo e classificação unknown. `None`, falhas e regras desabilitadas não são convertidas em evidência favorável. A contagem de cobertura é exposta em `scan.stats`; uma análise com baixa cobertura continua exigindo interpretação pelo host.

O orçamento de três famílias evita que o número de regras defina a sensibilidade. Ele tem um limite deliberado: evidências abaixo das três mais fortes não aumentam a pontuação. As famílias são aproximações conservadoras de correlação, não independência estatística comprovada.

## Famílias

| Família | Regras |
|---|---|
| injection | process_injection |
| credentials | credential_access |
| persistence | persistence, service_installation |
| defense_evasion | defense_evasion |
| impact | destructive_commands, ransomware_artifacts |
| execution | download_and_execute, encoded_execution, suspicious_lolbin |
| obfuscation | anti_analysis, long_encoded_literal, packed_executable, dynamic_import_resolution |
| binary_layout | writable_executable, entrypoint_permissions, embedded_executable, overlapping_sections |
| masquerading | disguised_filename |
| collection | input_capture, screen_capture, clipboard_capture |
| privilege | token_manipulation |
| exfiltration | data_exfiltration |
| reputation | external_reputation |

Pesos são parâmetros de confiança relativa; a referência 3 e os pesos dos slots são constantes versionadas em `scoring/evidence.py`. Peso acima de 3 satura em 1; a reputação não pode produzir força acima de 1. Ela não constitui bloqueio absoluto. O host pode aplicar política própria utilizando `target.reputation`.

`scan.scoring` expõe todas as famílias, as regras vencedoras, os três slots, pesos, média bruta, k e versão do modelo. Isso permite reproduzir o valor sem pisos ou ajustes ocultos.

## Modelo anterior

```bash
python -m scfs arquivo.exe --score-model legacy
```

```python
Settings(score_model="legacy")
```

Esse modo aplica `x = sum(score_i*peso_i)/sum(peso_i)` a todas as regras avaliadas e depois a mesma sigmoide. Ele usa as **25 regras e os indicadores atuais**, não reproduz exatamente a versão 1.0 de 14 regras. O modelo padrão agora é `grouped`; quem precisa conservar o tipo de agregação antigo deve selecionar `legacy` explicitamente.

## Classificação mantida do scurl

| Score | Verdict | Risk |
|---|---|---|
| < 10 | safe | very low |
| < 25 | safe | low |
| < 40 | suspicious | moderate |
| < 55 | suspicious | elevated |
| < 70 | dangerous | high |
| < 85 | dangerous | very high |
| >= 85 | malicious | critical |

A classificação usa o valor sem arredondamento; a apresentação usa duas casas. `safe` expressa poucos sinais, não garantia de segurança. Com k=5, o menor valor possível é 7,59 e o maior é 92,41. A escala nominal permanece 0–100. Pontuação não é probabilidade de malware.

## Escolha reproduzível de k

Foram comparados **4,5, 5, 6 e 7** com 12 controles sintéticos de validação, 4 controles reservados e 62 binários instalados no ambiente, presumidos legítimos (50 ELF e 12 PE, hashes distintos).

Critérios de engenharia:

- x=0 deve ficar abaixo de 10.
- x=0,35, representando um sinal forte isolado, deve ficar entre 25 e 55.
- x=0,85, representando evidências fortes de várias famílias, deve chegar a 85.
- Os 12 controles de validação devem respeitar suas faixas esperadas.

O menor candidato que satisfaz os critérios é **k=5**. k=4,5 não chega a 85 para x=0,85. Os quatro controles reservados também passaram para k=5. Nenhum dos 62 binários instalados foi classificado como suspeito; maior score 15,02. Uma das análises ficou partial porque atingiu o limite de extração de strings; as demais 61 ficaram ok. Essa cobertura parcial limita a conclusão sobre aquele arquivo. Esses arquivos e controles não são representativos de todo software legítimo e os controles reservados são variações próximas, não famílias independentes de malware.

O relatório completo fica em `calibration-report.json`. Para reproduzir os controles:

```bash
python -m scfs.calibration
python -m scfs.calibration --benign-file /bin/ls --benign-file /bin/echo
```

É possível fornecer corpus próprio com rótulos e separação explícita:

```json
{
  "samples": [
    {"path": "validation/legit.exe", "label": "benign", "split": "validation"},
    {"path": "validation/sample.exe", "label": "malicious", "split": "validation"},
    {"path": "test/other.exe", "label": "benign", "split": "test"}
  ]
}
```

```bash
python -m scfs.calibration --manifest corpus.json
```

Caminhos relativos são resolvidos contra o diretório do manifesto. O utilitário nunca executa arquivos. Os rótulos pertencem a quem prepara o corpus. Duplicados por SHA-256 são removidos; rótulos conflitantes ou o mesmo hash em validation/test causam erro. Isso não remove variantes da mesma família: a separação por família/origem continua responsabilidade de quem monta o corpus.

A seleção filtra os critérios de engenharia, minimiza `5*FPR + FNR` no corpus **de validação** quando fornecido e desempata pelo menor k. O peso 5 é uma política explícita de custo para falso alarme, ajustável no código. Arquivos test e controles reservados não selecionam k. Erros de leitura/parse são reportados separadamente, não contados como acertos. Métricas de um conjunto sem malware não medem recall.

## Alcance da calibração

Esta é uma **calibração de engenharia**, com controles e um pequeno corpus presumido legítimo. Não existe corpus real de malware rotulado nesta entrega; logo `calibrated=false`, `calibration_scope="engineering_controls_only"` e `score_is_probability=false` permanecem na resposta. Não foi medida precisão/recall de detecção real nem foi feita calibração probabilística. Ajustar k não corrige indicadores ausentes ou regras incorretas.
