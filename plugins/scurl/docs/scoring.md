# Pontuação no scurl 1.2.0

O cálculo padrão agora é `grouped`. A agregação antiga continua disponível com `score_model="legacy"` ou `--score-model legacy` na CLI. O modo legacy usa as regras atuais; ele não reproduz exatamente o motor 1.1.0.

O modelo continua usando média ponderada e sigmoide, com **k=5**. A mudança está na agregação:

1. Cada regra produz valor 0–1 ou None se não houver dados aplicáveis.
2. Sua força é `min(valor, limite_da_regra) * min(peso/3, 1)`.
3. Cada família conserva apenas sua maior força, evitando somar indícios correlacionados.
4. As três famílias mais fortes ocupam slots de pesos 3, 2 e 1; slots vazios valem zero como falta de suporte.
5. A média bruta é `(3*a + 2*b + c)/6`.
6. A curva final é `100/(1 + exp(-k*(x-0.5)))`.

Os limites e as famílias ficam em `scoring/calibration.py`. Os pesos de infraestrutura, recursos de CDN e configurações de e-mail foram reduzidos em importância. Um certificado válido, o domínio antigo e o DNS saudável não apagam evidência de envio de senhas a outro domínio.

No modelo grouped, reputação tem uma política explícita: se o provider Safe Browsing retornar uma ameaça, a média bruta tem piso 0,95 antes da sigmoide. Com k=5 isso resulta em pelo menos **90,47**. Erros HTTP/API, chave ausente e falhas de rede não são convertidos em reputação limpa. Os tipos de ameaça não identificam necessariamente phishing; malware e software indesejado também são sinalizados.

`scoring` expõe família, força, regra vencedora, slots, média e aplicação do piso. `rules` lista todas as regras, incluindo indisponíveis/falhas. `heuristics` conserva a lista de valores positivos para compatibilidade. `contribution` permanece o produto diagnóstico valor*peso; a contribuição efetiva para o cálculo agrupado está em `effective_strength` e nos slots de `scoring`.

As faixas de classificação permanecem: <10 very low/safe; <25 low/safe; <40 moderate/suspicious; <55 elevated/suspicious; <70 high/dangerous; <85 very high/dangerous; >=85 critical/malicious. A classificação usa o valor sem arredondamento.

A escala nominal é 0–100. Com k=5 os extremos atingíveis pela curva são 7,59 e 92,41. Score não é probabilidade de malware ou de phishing. Uma análise sem evidências suficientes não certifica segurança.

## Calibração e alcance

Foram avaliadas 96 combinações de k, pesos dos slots e limites lexicais. A seleção usou 2.000 URLs de desenvolvimento do PhiUSIIL (1.000 por classe), com objetivo explícito `FNR + 5*FPR`, além de duas restrições: cenário neutro abaixo de 10 e HTTP isolado abaixo de 25. Esse custo prefere reduzir falsos alertas, aceitando mais falsos negativos.

A combinação escolhida manteve k=5, slots 3/2/1 e limite 0,6 para entropia do domínio/subdomínio. Valores genéricos de infraestrutura não foram transformados em certezas. Outros limites são decisões de engenharia documentadas no código, não parâmetros aprendidos no conjunto de teste.

A avaliação final usou mais 2.000 URLs, com domínios registráveis distintos do desenvolvimento e de uma amostra exploratória intermediária. Nenhuma URL do dataset foi visitada. O dataset fornece URLs/atributos históricos; este experimento usa **somente a string da URL**, sem reconstruir HTML, TLS, DNS, RDAP ou reputação a partir de atributos precomputados.

No teste final, falsos positivos passaram de 8,2% para 0,9%, enquanto recall passou de 57,8% para 47,4%. Logo não há melhora universal de detecção. As correções dos formulários e JavaScript foram verificadas separadamente com HTML sintético. A detecção completa precisa de corpus independente com HTML/metadata e medições em ambiente com rede funcional. `calibrated=false` permanece: isto não é calibração probabilística nem validação do scanner completo em produção.

Consulte `evaluation-report.md` e `evaluation-report.json` para métricas, limites, scripts, parâmetros e origem dos dados.
