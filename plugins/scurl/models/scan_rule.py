from dataclasses import dataclass
from plugins.scurl.models.scan_result import ScanResult 

@dataclass
class ScanRule:
    """
        Classe base para definir regras de verificação de segurança.

        Uma ScanRule encapsula um padrão de verificação de segurança que pode ser executado
        em diversos contextos para identificar possíveis vulnerabilidades ou problemas de segurança.

        Atributos:
            name (str): O nome identificador da regra de verificação.
            category (str): A categoria da regra. Padrão: "url".
                Valores válidos: "url", "content", "architecture".
            severity (str): O nível de severidade dos problemas detectados por esta regra.
                Padrão: "low". Valores válidos: "low", "medium", "high".

        Métodos:
            run: Executa a regra de verificação contra o contexto fornecido.

        Levanta:
            NotImplementedError: Se run() for chamado sem ser implementado
                por uma subclasse.
    """

    name: str
    category: str = "url" 
    severity: str = "low"  
    
    def run(self, context: dict) -> ScanResult:
        raise NotImplementedError