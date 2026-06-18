from uuid import uuid4
from datetime import UTC, datetime
from plugins.scurl.models.scan_context import ScanContext

def meta_attribute(ctx: ScanContext, processors: int = 1) -> dict:
    """
        Meta attribute é uma função que adiciona atributos adicionais ao contexto de varredura. Esses atributos podem incluir informações como o timestamp da varredura, um identificador único para a varredura, um hash da URL e o número de threads usadas para a varredura. Esses atributos adicionais podem ser úteis para rastrear e analisar os resultados da varredura.

        Args:
            ctx (ScanContext): O contexto de varredura que será atualizado com os atributos adicionais.
            processors (int, optional): O número de threads usadas para a varredura. O padrão é 1.
    """
    
    ctx.meta.timestamp = datetime.now(UTC)
    ctx.meta.scan_id = uuid4().hex
    ctx.meta.threads = processors