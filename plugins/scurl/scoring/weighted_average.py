def weighted_average(scores: list, weights: list) -> float:
    """
        Calcula a média ponderada de uma lista de pontuações, onde cada pontuação é multiplicada por um peso correspondente. A média ponderada é a soma dos produtos das pontuações e seus pesos, dividida pela soma dos pesos. Se a soma dos pesos for zero, a função retorna 0 para evitar divisão por zero.
        
        Formula: 
            weighted_score = Σ(score_i * weight_i) / Σ(weight_i)
            onde:
                - score_i é a pontuação i-ésima
                - weight_i é o peso correspondente à pontuação i-ésima
                - weighted_score é a média ponderada resultante

        Atributos:
            scores (list): Uma lista de pontuações, onde cada elemento é um número.
            weights (list): Uma lista de pesos correspondentes às pontuações, onde cada elemento é um número.  
        
        Retorna:
            float: A média ponderada das pontuações.

        Exemplo:
            >>> weighted_average([0.5, 0.7], [0.2, 0.8])
            0.6666666666666666
            >>> weighted_average([0.5, 0.7], [0, 0])
            0.0
    """

    if len(scores) != len(weights):
        raise ValueError("scores and weights must have same length")

    numerator = sum(s * w for s, w in zip(scores, weights) if s is not None)
    denominator = sum(w for s, w in zip(scores, weights) if s is not None)

    if denominator == 0:
        return 0.0

    return numerator / denominator