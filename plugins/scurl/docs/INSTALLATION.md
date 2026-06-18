# Instalação

O scurl usa **setuptools** como build backend e **uv** como gerenciador de pacotes recomendado. O projeto requer Python 3.11 ou superior.

---

## Requisitos

- Python >= 3.11
- [uv](https://docs.astral.sh/uv/) (recomendado) ou pip
- Git

---

## Instalação via uv (recomendado)

### Windows

```powershell
# Instalar uv
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Clonar e instalar
git clone https://github.com/JuaanReis/scurl.git
cd scurl
uv sync
```

### Linux / macOS

```bash
# Instalar uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clonar e instalar
git clone https://github.com/JuaanReis/scurl.git
cd scurl
uv sync
```

---

## Instalação via pip

```bash
git clone https://github.com/JuaanReis/scurl.git
cd scurl
pip install -e .
```

No Linux/macOS, se `pip` não estiver disponível ou for o pip do sistema, use `pip3` ou `python3 -m pip`.

---

## Verificando a instalação

Após instalar, os dois entry points ficam disponíveis:

```bash
scurl --help
scurl-api
```

---

## Uso

### CLI

```bash
scurl https://example.com
```

Veja [CLI Reference](cli.md) para todos os argumentos e flags.

### API

```bash
scurl-api
```

Isso inicia o servidor uvicorn com as configurações definidas em `config["server"]`. Por padrão, o servidor sobe em `http://localhost:8000`.

Para subir o servidor manualmente com controle de reload (desenvolvimento):

```bash
uvicorn app.api.server:app --reload
```

Veja [API Reference](api.md) para os endpoints disponíveis.

---

## Dependências

As dependências são declaradas no `pyproject.toml` e instaladas automaticamente pelo `uv sync` ou `pip install -e .`:

| Pacote | Versão |
|---|---|
| fastapi | 0.136.1 |
| uvicorn | 0.47.0 |
| pydantic | 2.13.4 |
| httpx | 0.28.1 |
| selectolax | 0.4.7 |
| cryptography | 48.0.0 |
| slowapi | 0.1.9 |
| tldextract | 5.3.1 |
| ipwhois | 1.3.0 |
| colorama | >= 0.4.6 |
| tomli | >= 2.0.1 (Python < 3.11 apenas) |