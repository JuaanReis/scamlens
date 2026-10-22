"""Registra a rota do SCPIX no api/server.py de modo idempotente.

Executar na raiz do repositório: python -m plugins.scpix.install_api
"""
from pathlib import Path


IMPORT_LINE = "from api.router.scpix.pix import router as scpix_analyze_router"
ROUTER_LINE = 'app.include_router(scpix_analyze_router, prefix="/api/scpix")'


def integrate(root: Path) -> bool:
    server = root / "api" / "server.py"
    if not server.is_file():
        raise FileNotFoundError("api/server.py não encontrado; execute na raiz do ScamLens")
    text = server.read_text(encoding="utf-8")
    anchor_import = "from api.router.scfs.file import router as scfs_analyze_router"
    anchor_router = 'app.include_router(scfs_analyze_router, prefix="/api/scfs")'
    if (IMPORT_LINE in text) != (ROUTER_LINE in text):
        raise ValueError("integração parcial detectada em api/server.py; revise manualmente")
    if IMPORT_LINE in text:
        return False
    if text.count(anchor_import) != 1 or text.count(anchor_router) != 1:
        raise ValueError("âncoras do SCFS não encontradas exatamente uma vez; não alterei api/server.py")
    updated = text.replace(anchor_import, anchor_import + "\n" + IMPORT_LINE, 1)
    updated = updated.replace(anchor_router, anchor_router + "\n" + ROUTER_LINE, 1)
    server.write_text(updated, encoding="utf-8")
    return True


def main():
    changed = integrate(Path.cwd())
    print("SCPIX: rota integrada." if changed else "SCPIX: rota já integrada.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
