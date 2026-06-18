from math import exp

def domain_age_score(age_days: int | None, tau: float = 730) -> float:
    """
        A função domain_age_score é projetada para avaliar o risco associado à idade de um domínio. Domínios mais antigos tendem a ser mais confiáveis, pois têm um histórico mais longo e são menos propensos a serem usados para atividades maliciosas. A função utiliza uma fórmula exponencial para atribuir um valor de risco com base na idade do domínio em dias. Quanto mais antigo for o domínio, menor será o valor de risco atribuído, com um limite máximo de 1.0 para domínios muito antigos. Se a idade do domínio não estiver disponível (age_days for None), a função retorna um valor de risco neutro de 0.5. 

        Atributos:
            - age_days (int | None): A idade do domínio em dias. Pode ser None se a informação de criação do domínio não estiver disponível.
            - tau (float): O parâmetro de decaimento que controla a taxa de diminuição do risco com o aumento da idade do domínio. O valor padrão é 365, o que significa que o risco diminui significativamente para domínios com mais de um ano de idade.
        
        Retorna:
            float: O valor de risco associado à idade do domínio, variando entre 0.0 (domínio muito antigo) e 1.0 (domínio muito recente), com um valor neutro de 0.5 para casos onde a idade não está disponível.
        
        Exemplo de uso:
        ```
            score = domain_age_score(30)  # Domínio com 30 dias de idade
            print(score)  # Saída: valor de risco associado à idade do domínio
        ```
    """

    if age_days is None:
        normalized = 0.5

    else:
        age_days = max(age_days, 0)
        normalized = exp(-age_days / tau)

        if normalized < 0.001:
            normalized = 0.0

    return normalized