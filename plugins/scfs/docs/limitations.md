# Limites e validação

## Escopo real

A ferramenta procura **indicadores estáticos**, não comprova comportamento. Um texto citando um comando pode gerar alerta; malware ofuscado pode não gerar nenhum. Strings de HTTP, virtualização, criptografia ou API isolada não provam malícia. Ferramentas de desenvolvimento e administração podem compartilhar os mesmos indicadores.

PE: importa símbolos por nome da tabela convencional; não resolve ordinais nem delay imports, e pode perder importações empacotadas. ELF e Mach-O não extraem símbolos de funções dinâmicas; usam strings e estrutura; Mach-O extrai nomes de dylibs. ELF usa segmentos LOAD no campo comum `sections`, não a tabela de seções. Mach-O não valida permissões do entrypoint, pois não o resolve. Para universal, as regiões são relativas a cada fatia, identificadas por `archN:`. Campos `architectures` conservam as estruturas de cada fatia.

Entropia usa até 64 KiB por região: inteira se pequena; quatro blocos distribuídos se grande. `entropy_sample_bytes` explicita a amostragem. Uma região de alta entropia pode ser conteúdo legítimo comprimido. A regra de overlay não existe: `overlay_bytes` é apenas metadado PE e pode incluir certificado ou dados legítimos. Assinatura digital tem status `not_verified` e não reduz score. Em ELF é `not_applicable`.

Linhas inteiras de comentário são removidas conforme a extensão: # em Python/PowerShell/shell, REM/:: em batch, // em JS e apóstrofo em VBS. Não são removidos comentários inline ou blocos; strings multilinha e construções ambíguas podem ser interpretadas incorretamente. Essa filtragem lexical reduz alguns falsos positivos e pode causar falsos negativos. Não equivale a parsing da linguagem.

Scripts são texto: não há AST, resolução de variáveis nem prova de que rede e execução pertençam ao mesmo fluxo. O scanner não avalia expressões para decodificar payloads. Indicadores são substrings case-insensitive; isso pode causar falso positivo. Strings extraídas de binários têm no mínimo 5 caracteres e no máximo 512 por ocorrência, em ASCII e UTF-16LE. No limite padrão de 30 mil strings, a resposta fica `partial`. Não inclui UTF-16BE em binários; scripts com BOM UTF-16BE são decodificados.

## Recursos

Arquivo padrão máximo 64 MiB, configurável até 512 MiB; snapshot em memória para que hash e heurísticas usem os mesmos bytes. O processo lê no máximo limite+1 do caminho, rejeita arquivos especiais e detecta alterações comuns de tamanho/data durante leitura. Bytes já carregados pelo host devem ter tamanho limitado antes da chamada. Pode haver mais de uma cópia temporária de dados; não é streaming nem sandbox.

Limites: 96 seções PE, 128 program headers ELF, 4096 comandos/128 segmentos Mach-O e 32 fatias universais. Arquivos válidos fora desses limites podem ser rejeitados. Falhas de parse retornam erro, nunca classificação safe. Não há promessa de suporte completo aos formatos; parsers em Python verificam limites antes das leituras estruturadas. Não há isolamento de processo ou timeout de CPU interno; o host pode impor limites externos.

## Testes

Execute a partir da pasta pai:

```bash
python -m unittest scfs.tests.test_engine scfs.tests.test_v110 -v
```

A suíte cobre PE32/64, ELF32/64 em ambas as ordens, Mach-O32/64 em ambas as ordens, Mach-O universal, scripts e UTF-16, pontuação, fontes inválidas, provider opcional e falha de provider, regras desativadas, limites, CLI JSON/códigos e centenas de truncamentos/mutações determinísticos. Fixtures são estruturas mínimas inertes, não arquivos maliciosos reais.

Na versão 1.1 foram feitos 23 testes automatizados e uma avaliação estática de 62 binários instalados (50 ELF e 12 PE), presumidos legítimos, além de 16 controles sintéticos. Não há corpus real malicioso para medir detecção; os resultados e os candidatos de k estão em calibration-report.json. Nenhum alvo foi executado pelo scanner. Não houve consulta a serviços de reputação.

## Origem arquitetural

Arquitetura e fórmulas verificadas em `plugins/scurl` do repositório https://github.com/JuaanReis/scamlens (commit registrado em `REFERENCE.txt`). O scfs é independente: não copia dependências de URL, banco, rede, QR ou imports absolutos do scurl. Mantém os conceitos de contexto, registro RuleEntry, pipeline, classificação e retorno `(scan, target)`.
