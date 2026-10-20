# Integração do scurl 1.2.0

A integração local conecta as seis novas regras ao registro e centraliza pesos, parâmetros, grupos e limites em `scamLens/config.toml`. As novas funções seguem o padrão dos módulos antigos: entradas tipadas, `ResultBase` com argumentos nomeados e documentação em português.

O retorno permanece `(scan, target)`, com a assinatura posicional anterior. Exemplo:

```python
scan, target = run_engine(url)
scan, target = run_engine(url, score_model="grouped")
```

`legacy` permanece como modelo padrão. `grouped` é uma política opcional de engenharia: usa o maior sinal ponderado de cada grupo após os limites individuais. Os scores não são probabilidades e não foram calibrados com um dataset nesta integração.

A resposta recebe `scan.scoring`, com modelo, k e identificação da configuração. Cache antigo ou incompatível é ignorado. O banco não recebeu alterações de esquema nesta integração. Rotas continuam retornando os campos anteriores.

A CLI lê os mesmos defaults da API, aceita as opções anteriores e emite JSON UTF-8 com `-o -`. Saídas: 0 para execução concluída, 2 para erro de entrada/execução, 130 para interrupção. O formato JSON anterior foi preservado.

Correções incluem revogação do access token no logout, rollback no cadastro duplicado, cotas anônimas diárias, URL de avatar acessível por HTTP, limite de upload QR, redirects relativos e validação de porta. Formulários, favicon, imagens e scripts compartilham a resolução de recursos, inclusive o elemento base. A avaliação de scripts não faz mais consultas de ASN; a PSL usa o snapshot instalado sem downloads implícitos nas regras.

A documentação anterior descrevia recursos de um patch que não estava aplicado por completo nesta pasta. Esta versão do documento descreve apenas a integração presente. Não há contrato novo de status partial, benchmark de dataset, limite de corpo HTTP ou garantia de proteção completa contra DNS rebinding nesta entrega.

Instruções de reprodução e limites estão em `docs/TESTING.md`, na raiz do projeto.
