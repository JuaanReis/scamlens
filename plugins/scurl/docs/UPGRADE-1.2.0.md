# Integração do scurl 1.2.0

Base revisada: ScamLens commit `0c80ac6`, motor scurl 1.1.0. O pacote de entrega contém um patch contra essa base, relatório e instruções. Não foram feitas alterações remotas no repositório.

## Aplicar

Na raiz do projeto, com suas alterações locais preservadas em branch/commit:

```bash
git apply --check /caminho/scurl-1.2.0.patch
git apply /caminho/scurl-1.2.0.patch
python -m unittest discover -s tests/scurl -v
```

Se a checagem falhar, compare o patch com sua versão antes de aplicar; ele inclui mudanças em **plugins/scurl, providers, esquema da API e configuração**. Copiar somente o motor deixará chamadas de providers e o esquema incompatíveis. Não substitua suas configurações personalizadas por uma configuração inteira de outra versão: o patch acrescenta apenas `score_model="grouped"` e `cache_ttl_seconds=300` na seção existente `scurl.scanner`.

A assinatura posicional original de `run_engine` foi preservada. O novo argumento opcional é keyword-only:

```python
scan, target = run_engine(url, score_model="grouped")
scan, target = run_engine(url, score_model="legacy")
```

O retorno continua `(scan, target)`. Não há alterações nas tabelas SQL. As dependências de runtime permanecem as do projeto; Black foi usado somente como ferramenta de formatação no desenvolvimento.

## Mudanças de contrato

- Modelo padrão grouped, k=5; as notas mudam em relação à versão anterior.
- `scan.status` pode ser **partial**, com resultado válido e avisos de cobertura. O frontend deve apresentar o resultado e os avisos, além de tratar ok/error.
- Campos adicionais: `scan.rules`, `warnings`, `coverage`, `timings`, `scoring`; campos antigos foram mantidos.
- `spf`, `dmarc` e `has_mx` podem ser null: consulta de e-mail não realizada não significa ausência de configuração.
- A CLI usa saída 0 para classificação safe, 1 para risco sinalizado e 2 para erro (130 se interrompida). O formato JSON original da CLI foi preservado; o envelope HTTP continua sendo o da API.
- `use_cache=False` não persiste automaticamente: as rotas da API já salvam a análise. A CLI com `--cache` inicializa o banco e usa o cache.
- Cache de scan tem validade padrão de 300 segundos e exige versão do motor, modelo e k compatíveis; destino é validado antes do cache. Caches antigos são ignorados.
- Hashes distinguem www/apex, credenciais na autoridade e barras finais; esses alvos não são necessariamente equivalentes.

## Coleta e segurança

Até dois workers de I/O por scan. Regras locais são sequenciais e não fazem rede; consultas de ASN foram removidas das heurísticas. O HTML usa a URL final e o elemento base para resolver recursos. A cadeia de redirects é preservada, destinos relativos e `//host` são resolvidos corretamente, loops são encerrados e cada destino passa por validação.

São verificadas todas as respostas A/AAAA do resolvedor do sistema. O HTTP de alvo usa IP validado e mantém Host/SNI originais. Conexões HTTP de alvos fixados são fechadas para não reutilizar TLS entre nomes distintos que compartilham IP. Isso tem custo de conexão em rede real, não medido no benchmark simulado. A verificação TLS original permanece habilitada. Userinfo da URL não é enviado como Basic Auth ao alvo.

Safe Browsing consulta a cadeia de URLs em lote, por provider. Não existe chave real de Safe Browsing no pacote; os positivos de reputação nos testes são respostas simuladas.

Resposta HTTP é limitada a 2 MiB de corpo decodificado. Conteúdo truncado, erros de coleta e páginas HTTP >=400 geram partial. O limite é de corpo retido, não uma garantia rígida de memória contra todos os formatos de compressão. O timeout por requisição/estágio não é um prazo global do scan; DNS do sistema, retries e filas também podem acrescentar tempo.

DNS consulta menos tipos de registro, sem remover www do alvo e com orçamento temporal. Políticas MX/SPF/DKIM não classificam phishing. Metadados TLS usam porta correta, validam hostname/cadeia e não fazem mais HEAD em URL de OCSP extraída do certificado; alcance HTTP não valida revogação, e channel binding não prova stapling.

A PSL vem do snapshot instalado do tldextract, sem download oculto durante heurísticas. A atualização do pacote deve ser mantida pelo projeto; tenants como alice.github.io e bob.github.io são tratados como proprietários distintos para recursos/formulários. RDAP continua consultando o domínio público de registro.

## As seis regras adicionadas

| Regra | Sinal |
|---|---|
| credential_cleartext | Senha em página HTTP ou enviada para destino HTTP |
| credential_exfiltration | Referência a senha, requisição e URL externa no mesmo script; não prova fluxo |
| misleading_link | Domínio exibido no texto do link diverge do destino |
| brand_subdomain | Domínio completo colocado como isca em um subdomínio de outro |
| unicode_mixed_script | Mistura de alfabetos no rótulo do domínio |
| cleartext_transport | HTTP como indício corroborativo; isoladamente fica abaixo do limiar de suspeita |

Também foram corrigidos form action, favicon relativo, redirecionamento JS, IP apenas no hostname, @ apenas na autoridade, XSS percent-encoded, índice de typos ausente e nomes de campos incoerentes. Campo de senha e certificado recém-emitido deixam de ser, por si sós, sinais fortes de golpe.

## Reproduzir a avaliação

Use os scripts de `tests/scurl` em processos separados. Não há contato com URLs de phishing nos benchmarks de dataset.

```bash
python tests/scurl/benchmark_fixtures.py . 5
python tests/scurl/benchmark_io.py .
python tests/scurl/benchmark_import.py .
python tests/scurl/prepare_uci.py /caminho/phiusiil.zip /caminho/amostras
python tests/scurl/calibrate.py . /caminho/amostras/development.json
python tests/scurl/benchmark_urls.py . 5 /caminho/amostras/final.json
```

`benchmark_io` simula cinco providers com 20 ms cada; não mede sua conexão. Para comparar com a base, execute os mesmos scripts apontando para um checkout limpo do commit 0c80ac6. A lógica de ASN da base é substituída por um stub no teste controlado; não foram inventadas latências de rede para esses lookups. O import foi medido em processos novos com caches do sistema operacional possivelmente aquecidos.

Dados: Prasad & Chandra (2024), PhiUSIIL Phishing URL (Website), UCI, CC BY 4.0. Label 1=legítimo, 0=phishing. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset . O arquivo bruto não acompanha a entrega; baixe a versão indicada no relatório para reproduzir as amostras.
