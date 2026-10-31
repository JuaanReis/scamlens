def minmax(value: float, min_v: float, max_v: float) -> float:
    """
        Normaliza um valor usando a técnica de Min-Max Scaling.

        Args:
            value (float): O valor a ser normalizado.
            min_v (float): O valor mínimo do intervalo original.
            max_v (float): O valor máximo do intervalo original.

        Returns:
            float: O valor normalizado entre 0 e 1.
        Exemplo:
            ```
                >>> minmax(75, 0, 100)
                0.75
                >>> minmax(50, 0, 100)
                0.5
                >>> minmax(25, 0, 100)
                0.25
            ``` 
    """

    if max_v == min_v:
        return 0.0
    
    return min((value - min_v) / (max_v - min_v), 1.0)
    
def normalize_counter(value: int, threshold: int) -> float:
    """
        Normaliza um valor de contagem usando a técnica de normalização por limite.

        Args:
            value (int): O valor a ser normalizado.
            threshold (int): O limite máximo do intervalo original.

        Returns:
            float: O valor normalizado entre 0 e 1.
        Exemplo:
            ```
                >>> normalize_counter(75, 100)
                0.75
                >>> normalize_counter(50, 100)
                0.5
                >>> normalize_counter(25, 100)
                0.25
            ``` 
    """
    if threshold <= 0:
        return 0.0
    
    return min(value / threshold, 1.0)