from plugins.scurl.parsers.url_structure_extract import extract_structure

def get_structure(url: str) -> dict:
    """
        Extrai a estrutura de um URL, incluindo informações como o domínio, subdomínio, caminho, etc.
        Retorna um dicionário com a estrutura do URL, onde as chaves são os tipos de informações extraídas e os valores são os dados correspondentes. Se a estrutura não puder ser extraída, retorna um dicionário vazio.
    """
    structure = extract_structure(url) or {}
    structure["html_parser"] = None
    structure["rdap"] = None
    return structure