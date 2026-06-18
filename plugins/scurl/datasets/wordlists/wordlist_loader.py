from typing import Generator, Any

def domain_generator(path: str) -> Generator[str, Any, None]:
    """
        Gera nomes de domínio a partir de um arquivo de lista de palavras.
        Esta função geradora lê um arquivo linha por linha e retorna cada linha
        como um nome de domínio sem espaços em branco, removendo qualquer espaço
        em branco no início ou no final.

        Args:
            path (str): O caminho do arquivo contendo a lista de domínios.

        Yields:
            str: Cada nome de domínio do arquivo, com espaços em branco removidos.

        Raises:
            FileNotFoundError: Se o arquivo especificado não existir.
            IOError: Se houver um erro ao ler o arquivo.

        Example:
            >>> for domain in domain_generator('domains.txt'):
            ...     print(domain)
    """

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                yield line.strip()
    except FileNotFoundError as e:
        return 