from collections import Counter
from math import log2

def shannon_entropy(text: str) -> float:
    """
        Calcula a entropia de Shannon de uma string.
    
        A entropia mede o nível de aleatoriedade ou imprevisibilidade
        dos caracteres presentes no texto. Valores mais altos indicam
        maior diversidade de caracteres, o que pode sugerir dados
        ofuscados, codificados ou gerados aleatoriamente.
    
        Fórmula:
            H(X) = - Σ (p(x_i) * log2(p(x_i)))
            onde:
                - X é o conjunto de caracteres da string
                - p(x_i) é a probabilidade do caractere x_i
                - H(X) é a entropia da string
    
        Args:
            text (str): Texto que será analisado para cálculo da entropia.
    
        Returns:
            float: Valor da entropia calculada. Retorna 0.0 caso o texto
            esteja vazio.
    """

    if not text:
        return 0.0
    
    freq = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)

    return max(entropy, 0.0)