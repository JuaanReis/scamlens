# As 25 heurísticas

Valores abaixo são máximos de cada regra, antes da ponderação. Não representam probabilidades. Uma capacidade legítima pode compartilhar indicadores com malware. Evidências de texto são coocorrências, não prova de chamadas reais ou fluxo de dados.

| ID | Peso | Score máximo | Critério |
|---|---:|---:|---|
| process_injection | 3,0 | 1,00 | Combinação de APIs de alocação/escrita/injeção |
| credential_access | 3,0 | 0,95 | Vários indicadores de acesso a credenciais |
| persistence | 1,8 | 0,75 | Indicadores de autorun/tarefas/cron |
| defense_evasion | 2,5 | 0,95 | Indicadores de alteração de defesas/logs |
| destructive_commands | 3,0 | 1,00 | Exclusão de backups e comandos de impacto; limpeza recursiva isolada é fraca |
| download_and_execute | 2,5 | 0,85 | Download específico e execução dinâmica; URL + criação de processo genéricas valem apenas 0,12 |
| encoded_execution | 2,0 | 0,85 | Codificação junto a execução dinâmica |
| anti_analysis | 1,0 | 0,50 | Vários indicadores de depuração/virtualização |
| long_encoded_literal | 0,6 | 0,30 | Literal >= 300 caracteres compatível com base64 |
| writable_executable | 2,0 | 0,70 | Região simultaneamente gravável e executável |
| packed_executable | 1,2 | 0,60 | Nome de empacotador junto a entropia alta |
| entrypoint_permissions | 1,0 | 0,60 | Entrypoint fora de região executável mapeada |
| disguised_filename | 1,0 | 0,65 | Dupla extensão de documento ou controle bidirecional |
| external_reputation | 4,0 | 1,00 | Fração de detecções do provider externo |
| input_capture | 1,8 | 0,80 | API de teclado combinada com contexto de captura |
| screen_capture | 0,8 | 0,50 | API de screenshot combinada com contexto gráfico |
| clipboard_capture | 0,8 | 0,45 | Leitura de clipboard e contexto de monitoramento |
| service_installation | 1,5 | 0,70 | Criação de serviço e API/configuração complementar |
| token_manipulation | 2,5 | 0,85 | Impersonação/duplicação de token e contexto de privilégios |
| ransomware_artifacts | 3,0 | 1,00 | Texto de resgate junto a criptografia e modificação de arquivos; criptografia isolada não pontua |
| data_exfiltration | 2,5 | 0,90 | Envio junto a referências a dados sensíveis e compactação |
| suspicious_lolbin | 2,5 | 0,85 | Binário de sistema citado junto a rede/codificação |
| dynamic_import_resolution | 0,8 | 0,30 | Resolução de símbolo e carregamento de biblioteca; indício fraco |
| embedded_executable | 1,0 | 0,40 | PE embutido com assinatura/cabeçalhos mínimos coerentes |
| overlapping_sections | 1,5 | 0,65 | Seções PE sobrepostas em arquivo ou endereço virtual |

A regra de PE embutido examina no máximo 64 candidatos MZ, verifica limites e assinatura PE, número de seções e tamanho mínimo de cabeçalhos. Não faz parse recursivo nem prova que o conteúdo é executável válido. Instaladores com executáveis embutidos podem acionar essa regra. Limite de busca atingido reduz a cobertura e produz `partial`.

Sobreposição é avaliada somente em PE; sobreposições de segmentos ELF/Mach-O podem fazer parte de layouts legítimos. Regras estruturais não aplicáveis retornam None, assim como reputação ausente.

Os indicadores ficam em `datasets/indicators.json`. O texto de evidência e características são calculados uma vez por arquivo em `parsers/features.py`; as regras não executam chamadas externas.

## Referências conceituais

As correspondências com ATT&CK descrevem capacidades, não garantem que uma amostra realize a técnica:

- Keylogging, T1056.001: https://attack.mitre.org/techniques/T1056/001/
- Screen Capture, T1113: https://attack.mitre.org/techniques/T1113/
- Clipboard Data, T1115: https://attack.mitre.org/techniques/T1115/
- Windows Service, T1543.003: https://attack.mitre.org/techniques/T1543/003/
- Access Token Manipulation, T1134: https://attack.mitre.org/techniques/T1134/
- System Binary Proxy Execution, T1218: https://attack.mitre.org/techniques/T1218/
- Especificação PE da Microsoft: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

Essas fontes fundamentam os conceitos e o formato; não validam os pesos, thresholds ou a eficácia do scfs. Os parâmetros desta ferramenta são decisões de engenharia documentadas em scoring.md.
