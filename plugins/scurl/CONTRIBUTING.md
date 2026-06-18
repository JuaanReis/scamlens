# Contribuindo para o SCURL

Obrigado por considerar contribuir com o SCURL.

Este documento descreve o fluxo recomendado para contribuições, padronização de código, abertura de issues e envio de pull requests.

---

# Índice

- [Ambiente de desenvolvimento](#ambiente-de-desenvolvimento)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Padrões de código](#padrões-de-código)
- [Commits](#commits)
- [Pull Requests](#pull-requests)
- [Reportando bugs](#reportando-bugs)
- [Sugestões de heurísticas](#sugestões-de-heurísticas)
- [Checklist antes do PR](#checklist-antes-do-pr)

---

# Ambiente de desenvolvimento

Clone o repositório:

```bash
git clone https://github.com/JuaanReis/scurl.git
cd scurl
```

Crie um ambiente virtual:

```bash
python -m venv .venv
```

Ative o ambiente:

### Linux/macOS

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Instale o projeto em modo de desenvolvimento:

```bash
pip install -e .
```

---

# Estrutura do projeto

```text
scurl/
├── core/               # Motor principal de análise
├── providers/          # DNS, SSL, Safe Browsing, cache, etc
├── datasets            # Dados de base para heurísticas
├── app/                # API REST (FastAPI)
├── docs/               # Documentação
└── assets/             # Recursos visuais
```

---

# Padrões de código

Para manter consistência no projeto:

- utilize Python 3.10+
- prefira tipagem explícita
- mantenha funções pequenas e reutilizáveis
- evite lógica duplicada
- mantenha heurísticas isoladas e independentes
- documente comportamentos não triviais

---

# Commits

Prefira commits objetivos e descritivos.

Exemplos:

```text
feat: adiciona heurística para URLs encurtadas
fix: corrige cálculo de score SSL
refactor: simplifica pipeline de execução
docs: atualiza documentação da API
```

---

# Pull Requests

Antes de abrir um Pull Request:

1. crie uma branch separada
2. mantenha o PR focado em uma alteração específica
3. descreva claramente o problema resolvido
4. inclua exemplos ou screenshots quando necessário
5. atualize documentação relevante

Exemplo:

```bash
git checkout -b feat/new-heuristic
```

---

# Reportando bugs

Ao abrir uma issue de bug, inclua:

- versão utilizada
- sistema operacional
- comando executado
- comportamento esperado
- comportamento observado
- traceback completo (se existir)

Quanto mais detalhes forem fornecidos, mais fácil será reproduzir o problema.

---

# Sugestões de heurísticas

Novas heurísticas são bem-vindas.

Ao sugerir uma heurística:

- explique o sinal analisado
- descreva o impacto esperado no score
- informe possíveis falsos positivos
- explique custo de execução/rede
- descreva dependências externas (se houver)

---

# Checklist antes do PR

Antes de enviar:

- [ ] código testado localmente
- [ ] documentação atualizada
- [ ] sem imports não utilizados
- [ ] sem código comentado desnecessário
- [ ] sem credenciais ou chaves expostas
- [ ] sem quebra de compatibilidade conhecida

---

# Segurança

Não envie:

- chaves de API
- credenciais
- tokens
- bancos de dados reais
- URLs sensíveis de terceiros

---

# Licença

Ao contribuir com o projeto, você concorda que seu código será distribuído sob a licença [MIT](./LICENSE).