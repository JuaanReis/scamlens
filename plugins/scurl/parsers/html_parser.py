from selectolax.parser import HTMLParser

def parse_html(body: str) -> HTMLParser:
    """
        Parseia o conteúdo HTML e retorna um objeto HTMLParser para análise posterior.

        Args:
            body (str): O conteúdo HTML a ser analisado.
            
        Returns:
            HTMLParser: Um objeto HTMLParser contendo a estrutura do HTML para análise.
    """
    return HTMLParser(body)