def parse_issuer(issuer: list) -> dict:
    """
        Faz parser do campo "issuer" do certificado SSL, extraindo as informações relevantes sobre a autoridade certificadora (CA) que emitiu o certificado. O campo "issuer" é uma lista de tuplas, onde cada tupla contém um par chave-valor representando um atributo do emissor do certificado. A função percorre essa lista e constrói um dicionário com as informações extraídas, facilitando o acesso aos detalhes do emissor para análises posteriores.

        Atributos:
            - issuer (list): Lista de tuplas representando o campo "issuer" do certificado SSL, onde cada tupla contém um par chave-valor (por exemplo, ("CN", "Let's Encrypt Authority X3")). 
        
        Retorna:
            dict: Dicionário contendo as informações extraídas do campo "issuer", onde as chaves são os atributos do emissor (por exemplo, "CN", "O", "C") e os valores correspondentes são as informações associadas a esses atributos (por exemplo, "Let's Encrypt Authority X3", "Let's Encrypt", "US").

        Exemplo de uso:
        ```
        issuer_info = parse_issuer([   
            (("CN", "Let's Encrypt Authority X3"),),
            (("O", "Let's Encrypt"),),
            (("C", "US"),)
        ])
        print(issuer_info)
        # Saída:
        # {
        #     "CN": "Let's Encrypt Authority X3",
        #     "O": "Let's Encrypt",
        #     "C": "US"
        # }
        ```
    """
    result = {}

    for item in issuer:
        for key, value in item:
            result[key] = value

    return result