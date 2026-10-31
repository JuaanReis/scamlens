from difflib import SequenceMatcher

def string_similarity(a: str, b: str) -> float: 
    """
        Calcula a similaridade entre duas strings utilizando SequenceMatcher.
    
        A função utiliza o algoritmo interno do módulo `difflib` para
        comparar duas sequências de caracteres e determinar o grau de
        similaridade entre elas. O valor retornado varia entre 0 e 1,
        onde 0 indica nenhuma similaridade e 1 indica correspondência
        completa entre as strings.
    
        O algoritmo procura o maior trecho comum entre as strings e
        aplica a mesma lógica recursivamente para calcular a proporção
        de caracteres correspondentes no total das duas sequências.
    
        Fórmula:
            ratio = 2 * M / (|A| + |B|)
            onde:
                - M é o número total de caracteres iguais encontrados
                  nos blocos comuns
                - |A| é o tamanho da primeira string
                - |B| é o tamanho da segunda string
                - ratio é o valor de similaridade retornado (0.0 a 1.0)
    
        Args:
            a (str): Primeira string que será comparada.
            b (str): Segunda string que será comparada.
    
        Returns:
            float: Valor de similaridade entre as duas strings
            no intervalo de 0.0 a 1.0.
    """

    return SequenceMatcher(None, a, b).ratio()