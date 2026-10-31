import re

def similarity_jaccard(a: str, b: str) -> float:
    """
        Calcula a similaridade de Jaccard entre dois textos.
    
        A similaridade de Jaccard mede o grau de interseção entre dois
        ``conjuntos de palavras``. O valor retornado varia entre 0 e 1,
        onde 0 indica que os textos não compartilham palavras em comum
        e 1 indica que ambos possuem exatamente o mesmo conjunto de palavras.
    
        Os textos são divididos em palavras utilizando espaços e
        convertidos em conjuntos antes do cálculo.
    
        Fórmula:
            J(A, B) = |A ∩ B| / |A ∪ B|
            onde:
                - A é o conjunto de palavras do primeiro texto
                - B é o conjunto de palavras do segundo texto
                - |A ∩ B| é o tamanho da interseção entre A e B
                - |A ∪ B| é o tamanho da união entre A e B
    
        Args:
            a (str): Primeiro texto que será comparado.
            b (str): Segundo texto que será comparado.
    
        Returns:
            float: Valor da similaridade de Jaccard entre os dois textos.
            Retorna 0.0 caso ambos os textos resultem em conjuntos vazios.
    """

    set_a = set(re.findall(r'\w+', a.lower()))
    set_b = set(re.findall(r'\w+', b.lower()))

    intersection = set_a.intersection(set_b)
    union = set_a.union(set_b)

    if not union:
        return 0.0
    
    return len(intersection) / len(union)