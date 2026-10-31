def levenshtein(a: str, b: str) -> int:
    """
        Calcula a distância de Levenshtein entre duas strings.

        A distância de Levenshtein mede o número mínimo de operações
        necessárias para transformar uma string em outra. As operações
        permitidas são:
            - Inserção de um caractere
            - Remoção de um caractere
            - Substituição de um caractere

        Essa métrica é útil para medir similaridade ou detectar pequenas
        alterações em palavras, domínios ou textos, e é comumente utilizada
        em sistemas de detecção de phishing, correção automática e comparação
        de strings.

        Args:
            a (str): Primeira string a ser comparada.
            b (str): Segunda string a ser comparada.

        Returns:
            int: Distância de Levenshtein entre as duas strings,
                 indicando o número mínimo de operações necessárias
                 para transformá-las uma na outra.

        Example:
            >>> levenshtein("casa", "cassa")
            1
            >>> levenshtein("login", "logon")
            1
            >>> levenshtein("admin", "administrator")
            6
    """
    
    if a == b:
        return 0

    if len(a) < len(b):
        a, b = b, a

    previous = list(range(len(b) + 1))

    for i, ca in enumerate(a, 1):
        current = [i]

        for j, cb in enumerate(b, 1):
            insert_cost = current[j-1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j-1] + (ca != cb)

            current.append(min(insert_cost, delete_cost, replace_cost))

        previous = current

    return previous[-1]