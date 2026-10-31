def bigrams(s: str) -> list:
    """
        Gera uma lista de bigramas a partir de uma string.
        Um bigrama é uma sequência de dois caracteres consecutivos em uma string.
        Por exemplo, a string "phishing" geraria os seguintes bigramas:     ["ph", "hi", "is", "sh", "hi", "in", "ng"]
        
        Args:        
            s (str): A string da qual os bigramas serão gerados.

        Returns:        
            list: Uma lista de bigramas extraídos da string.

        Example:        
            >>> bigrams("phishing")        ["ph", "hi", "is", "sh", "hi", "in", "ng"]
    """

    return [s[i:i+2] for i in range(len(s)-1)]

def ngram_score(domain: str, model: dict) -> float:
    """
        Calcula a pontuação de um domínio com base em um modelo de bigramas.
        O modelo é um dicionário que mapeia bigramas para suas frequências em domínios legítimos.
        A pontuação é a média das frequências dos bigramas presentes no domínio, normalizada pelo comprimento do domínio.
        Domínios com bigramas raros ou inexistentes no modelo terão pontuações mais baixas, indicando maior risco de serem maliciosos ou gerados aleatoriamente.    
        Args:
            domain (str): O domínio a ser avaliado.
            model (dict): Dicionário de bigramas e suas frequências.

        Formula:
            score = (soma das frequências dos bigramas do domínio) / comprimento do domínio
        
        Returns:
            float: Pontuação de risco do domínio, onde valores mais baixos indicam maior risco.
    """
    score = 0

    for bg in bigrams(domain):
        score += model.get(bg, 0)

    return score / len(domain) if domain else 0