# Calibração e Limitações

O scurl é um sistema heurístico probabilístico. Por definição, não é determinístico, não substitui análise humana e não garante detecção absoluta. O objetivo do motor é maximizar contextualização, interpretabilidade e detecção de padrões — não produzir veredictos binários.

---

## Filosofia de calibração

A calibração busca equilibrar dois objetivos em tensão:

| Objetivo | Impacto |
|---|---|
| Sensibilidade | detectar ameaças reais |
| Conservadorismo | reduzir falsos positivos |

O sistema prioriza redução de falsos positivos em infraestruturas legítimas estabelecidas. Isso é implementado diretamente no sistema de dependências: quando `domain_age` é baixo (domínio antigo), os scores de `dns_score` e `ssl_score` são atenuados mesmo que os valores brutos sejam altos. O princípio é que sinais suspeitos em contexto estabelecido têm peso menor do que os mesmos sinais em contexto novo.

---

## Baselines observados

Os valores abaixo são baseados em testes reais com o motor em produção (v1.0.9).

### Infraestrutura legítima estabelecida

| Alvo | Score | Regras triggeradas | Observação |
|---|---|---|---|
| youtube.com | 8.32 | 5/36 (13.9%) | DNS e SSL atenuados por domain_age; SPA causa missing_form_tag e script_integrity_absent |
| Sites Google/CDN similar | 7–15 | — | Padrão esperado para infraestrutura corporativa consolidada |

### Infraestrutura suspeita

| Alvo | Score | Regras triggeradas | Observação |
|---|---|---|---|
| ca-app-49.info | 51.04 | 4/36 (11.1%) | Cert com 2 dias de idade, sem MX, hífens e proporção numérica alta no domínio |
| Phishing com typosquatting + campo de senha | 74–87 | — | Combinação de múltiplos sinais de alta severidade |
| Clone visual + domínio novo + form externo | 85+ | — | Convergência de sinais HTML e SERVER |

### Interpretação das faixas

| Score | Interpretação prática |
|---|---|
| 0–25 | Infraestrutura estabelecida, sinais normais |
| 26–50 | Sinais presentes — revisar contexto antes de concluir |
| 51–75 | Convergência de sinais suspeitos — investigação recomendada |
| 76–100 | Forte convergência heurística — alto risco |

---

## Casos conhecidos de falsos positivos

### Plataformas de hosting estático

Serviços como Netlify, Vercel, Cloudflare Pages e Framer frequentemente não têm MX, têm SPF ausente e usam TTL baixo. Isso ativa `dns_score` com valor alto. O sistema de dependências atenua esse sinal quando `domain_age` é baixo e `ssl_score` é saudável, mas plataformas recém-configuradas ou com domínios novos ainda podem pontuar acima do esperado.

### CDNs e edge networks

Infraestruturas CDN apresentam TTL baixo, múltiplos IPs e rotação de endereços — todos sinais que a heurística `dns_score` interpreta como suspeitos isoladamente. O sistema de dependências com `domain_age` e `random_domain_risk` mitiga isso, mas não elimina completamente o sinal em CDNs com domínio novo.

### SPAs e aplicações React/Vue

O HTML coletado pelo scurl é o HTML server-side. Aplicações que renderizam conteúdo via JavaScript retornam HTML mínimo, causando:

- `missing_form_tag` dispara mesmo em formulários legítimos renderizados client-side
- `script_integrity_absent` dispara para scripts externos sem SRI (padrão em muitos CDNs)
- Todas as outras heurísticas HTML retornam `None` — o score fica dependente de URL e SERVER

O youtube.com exemplifica isso: `missing_form_tag` e `script_integrity_absent` triggeraram com valores baixos (0.04) mas contribuição mínima (0.1 cada), absorvidos pelo contexto estabelecido via dependências.

### Domínios técnicos e APIs

Painéis administrativos, APIs e serviços internos usam paths com tokens, queries extensas e encoding misto. Heurísticas como `random_path_risk`, `base64_segments` e `query_contains_url` foram projetadas para isso — elas têm dependências de `domain_age` e `ssl_score` que atenuam o sinal em contextos legítimos.

---

## Limitações arquiteturais

### Conteúdo dinâmico

O scurl não executa JavaScript, não simula DOM runtime e não tem browser sandbox. Phishing renderizado client-side, lógica pós-load e conteúdo carregado dinamicamente não são analisados pelas heurísticas HTML. Para esses casos, o score depende exclusivamente das heurísticas de URL e SERVER.

### Dependência de disponibilidade externa

As heurísticas `domain_age`, `nameserver_diversity` e `rdap_metadata_incompleteness` dependem de resposta RDAP. `dns_score` depende de resolução DNS. `ssl_score` depende de conexão TLS. `safe_browsing` depende da API do Google. Falhas de rede ou indisponibilidade desses serviços fazem as heurísticas retornarem `None` ou scores conservadores, reduzindo a precisão contextual do scan.

O caso `ca-app-49.info` ilustra isso: a primeira tentativa HTTP deu timeout (`Tentativa 1/3 falhou`), aumentando o tempo total do scan para 11.25s e potencialmente afetando dados de timing.

### Google Safe Browsing

A API pública tem delay de atualização, cobertura parcial e limitação de quota. A heurística `safe_browsing` é complementar — não substitui análise estrutural. Um site recém-criado para phishing pode não estar indexado ainda.

### Taxa de trigger baixa

Em testes com sites legítimos, a taxa de trigger ficou entre 8–14% (3–5 regras de 36). Isso é esperado — a maioria das heurísticas retorna `None` quando o sinal não é aplicável. A taxa baixa **não indica falha do motor**: indica que o alvo não apresenta os padrões que as regras detectam. Uma taxa alta em site legítimo indica calibração inadequada ou falso positivo.

---

## O que o score não mede

O score do scurl mede convergência de sinais heurísticos, não intenção maliciosa comprovada. Um score de 51 não significa que o site é malicioso — significa que há sinais que justificam investigação adicional. Um score de 8 não garante que o site é seguro — significa que não há convergência de sinais suspeitos nos dados coletados.

O motor foi calibrado para ser útil como primeira triagem, não como sistema de bloqueio automático.