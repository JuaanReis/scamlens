# Sistema de Scoring

O scurl usa um modelo híbrido de três etapas: média ponderada, transformação sigmoide e resolução contextual via dependências. O objetivo é produzir um score probabilístico que separe com clareza infraestrutura legítima de suspeita, evitando acumulação linear excessiva de sinais moderados.

---

## Visão geral do fluxo

```
Resultados das heurísticas (normalized, weight)
        │
        ▼
apply_dependencies      ← ajusta normalized e weight com base em contexto
        │
        ▼
weighted_average        ← média ponderada dos valores ajustados
        │
        ▼
sigmoid(k=5)            ← transforma para escala 0–100
        │
        ▼
classify(score)         ← risk_level e verdict
```

---

## Etapa 1 — Filtragem

Antes de qualquer cálculo, o pipeline em `score.py` itera sobre `ctx.results` e filtra os resultados:

- `normalized = None` → heurística não aplicável, excluída completamente
- `normalized = 0` → sinal confirmado como baixo, também excluído para não inflar o denominador

Apenas resultados com `normalized > 0` entram no cálculo.

---

## Etapa 2 — Média ponderada

```python
weighted_score = Σ(score_i × weight_i) / Σ(weight_i)
```

Implementado em `core/scoring/weighted_average.py`. Pares onde `score` é `None` são ignorados tanto no numerador quanto no denominador — sem penalização por dados indisponíveis.

Se a soma dos pesos for zero (nenhuma heurística aplicável), retorna `0.0`.

**Exemplo:**

```python
weighted_average([0.5, 0.7], [0.2, 0.8])
# → (0.5×0.2 + 0.7×0.8) / (0.2 + 0.8) = 0.66
```

---

## Etapa 3 — Transformação sigmoide

```python
sigmoid(x) = (1 / (1 + exp(-k × (x - 0.5)))) × 100
```

Implementado em `core/scoring/sigmoid.py`. Recebe as listas de scores e weights e chama `weighted_average` internamente.

O parâmetro `k = 5` (padrão) controla a inclinação da curva. O ponto de inflexão está em `x = 0.5`, que mapeia para score `50`.

**Comportamento da curva com k=5:**

| Média ponderada | Score final |
|---|---|
| 0.10 | ~7.3 |
| 0.25 | ~18.2 |
| 0.50 | 50.0 |
| 0.75 | ~81.8 |
| 0.90 | ~92.7 |

A transformação sigmoide resolve o problema da linearidade: sinais moderados acumulam menos risco do que acumulariam numa média simples, e scores extremos (próximos de 0 ou 100) só aparecem quando há convergência forte de sinais.

**Por que k=5 e não outro valor?**

Com k=5, a curva é suficientemente sensível para separar infraestrutura limpa (8–15) de suspeita (50+) sem tornar o sistema agressivo demais. Valores maiores de k criariam uma transição mais abrupta — qualquer média ponderada acima de 0.5 seria mapeada para scores muito altos, aumentando falsos positivos.

---

## Etapa 4 — Resolução contextual (dependências)

Executada em `apply_dependencies` **antes** da média ponderada. Para cada heurística, o sistema verifica o `DEPENDENCIES` dict e aplica ajustes ao `normalized` e `weight` com base nos valores de outras heurísticas no `results_map`.

As três ações disponíveis:

| Ação | Efeito |
|---|---|
| `reduce` | Multiplica `normalized` pelo `factor` (< 1.0) — atenua o sinal |
| `increase` | Multiplica `normalized` pelo `factor` (> 1.0) — amplifica o sinal, cap em 1.0 |
| `skip` | Define `normalized = None` — remove a heurística do cálculo |

**Resolução de conflito:** quando `reduce` e `increase` disparam simultaneamente para a mesma heurística, `reduce` vence. Isso implementa o conservadorismo do sistema — falsos positivos são mais custosos do que falsos negativos em contextos de triagem.

---

## Etapa 5 — Classificação

O score final (0–100) é passado para `classify()` em `core/engine/analysis/classification.py`, que retorna `risk_level` e `verdict`:

| Score | risk_level | verdict |
|---|---|---|
| 0–20 | very low | safe |
| 21–40 | low | safe |
| 41–60 | medium | suspicious |
| 61–80 | high | suspicious |
| 81–100 | very high | unsafe |

---

## Contribuição por heurística

O campo `contribution` exibido na saída CLI e retornado pela API é calculado como:

```python
contribution = round(normalized_ajustado × weight_ajustado, 1)
```

Esse valor permite identificar quais heurísticas tiveram maior impacto no score final. Uma heurística com `value = 0.92` e `weight = 3.5` tem `contribution = 3.2` — muito mais impacto do que uma com `value = 0.04` e `weight = 2.0` (`contribution = 0.1`).

---

## Exemplo concreto

Scan do `ca-app-49.info` (score final: 51.04):

```
hyphen_risk:     normalized=0.40, weight=2.5  →  contribution=1.0
num_ratio_risk:  normalized=0.36, weight=2.0  →  contribution=0.7
dns_score:       normalized=0.92, weight=3.5  →  contribution=3.2
ssl_score:       normalized=0.26, weight=3.5  →  contribution=0.9
```

Média ponderada:
```
(0.40×2.5 + 0.36×2.0 + 0.92×3.5 + 0.26×3.5) / (2.5 + 2.0 + 3.5 + 3.5)
= (1.0 + 0.72 + 3.22 + 0.91) / 11.5
= 5.85 / 11.5
≈ 0.509
```

Sigmoid com k=5:
```
(1 / (1 + exp(-5 × (0.509 - 0.5)))) × 100 ≈ 51.2
```

O valor exato retornado foi 51.04 — a pequena diferença se deve aos ajustes aplicados por `apply_dependencies` antes do cálculo.