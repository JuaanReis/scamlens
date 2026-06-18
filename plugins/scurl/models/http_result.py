from dataclasses import dataclass

@dataclass
class HTTPResult:
    """
        Representa o resultado de uma requisição HTTP, encapsulando detalhes relevantes da resposta.
        A classe HTTPResult é utilizada para armazenar informações sobre a resposta de uma requisição HTTP, incluindo a URL final, status code, headers, corpo da resposta, tempo de resposta, tamanho do conteúdo e número de redirecionamentos.
        Atributos:
            - url (str): A URL final após possíveis redirecionamentos.
            - status (int): O código de status HTTP retornado pela resposta.
            - headers (dict): Um dicionário contendo os cabeçalhos da resposta HTTP.
            - body (str): O conteúdo do corpo da resposta HTTP como texto.
            - elapsed (float): O tempo total gasto para receber a resposta, em segundos.
            - size (int): O tamanho do conteúdo da resposta em bytes.
            - redirects (int): O número de redirecionamentos ocorridos durante a requisição. Padrão: 0.
        Exemplo de uso:
        ```
        result = HTTPResult(   
            url="https://www.exemplo.com",
            status=200,
            headers={"Content-Type": "text/html"},
            body="<html>...</html>",
            elapsed=0.35,
            size=1024,
            redirects=1
        )
        ```
    """
    
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float
    size: int
    redirects: int = 0
    redirect_chain: list = None