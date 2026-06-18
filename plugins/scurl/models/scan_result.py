from dataclasses import dataclass
from typing import Any

@dataclass
class ScanResult:
    """
        Representa o resultado de uma verificação de segurança.
        A classe ScanResult encapsula as informações sobre o resultado de uma verificação de segurança, incluindo o nome da verificação, o valor associado ao resultado, detalhes adicionais e o nível de severidade.  
        Atributos:
            - name (str): O nome identificador da verificação de segurança.
            - value (float): O valor associado ao resultado da verificação, que pode representar uma pontuação, probabilidade ou métrica relevante para a análise de segurança. Padrão: 0.0.
            - details (dict): Um dicionário opcional contendo informações adicionais ou contexto relevante sobre

        o resultado da verificação. Padrão: None.
        - severity (str): O nível de severidade do resultado, indicando a gravidade do problema de segurança identificado. Padrão: "low". Valores válidos: "low", "medium", "high".                     
        Exemplo de uso:

        ```
        result = ScanResult(
            name="Suspicious URL Pattern",
            value=0.85,
            details={"pattern": "example.com/login"},
            severity="high"
        )
        ```
    """
    
    name: str
    value: float = 0.0
    weight: float = 1.0
    details: dict = None
    severity: str = "low"
    category: str = "N/a"