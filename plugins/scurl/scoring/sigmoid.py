from math import exp
from .weighted_average import weighted_average

def sigmoid(scores: list, weights: list, k: int = 5) -> float:
    """
        Aplica a função sigmoide para transformar uma pontuação em uma escala de 0 a 100, onde a pontuação de 0.5 é o ponto de inflexão. O parâmetro k controla a inclinação da curva, com valores maiores resultando em uma transição mais abrupta entre as pontuações baixas e altas. A função retorna um valor entre 0 e 100, onde pontuações próximas a 0.5 resultam em valores próximos a 50, enquanto pontuações próximas a 0 ou 1 resultam em valores próximos a 0 ou 100, respectivamente.  
        
        Formula: 
            sigmoid(x) = (1 / (1 + exp(-k * (x - 0.5)))) * 100
            onde:
                - x é a pontuação média ponderada calculada a partir das listas de scores e weights
                - k é um parâmetro que controla a inclinação da curva sigmoide
                - sigmoid(x) é a pontuação transformada em uma escala de 0 a 100

        Atributos:
            scores (list): Uma lista de pontuações, onde cada elemento é um número.
            weights (list): Uma lista de pesos correspondentes às pontuações, onde cada elemento é um número.
            k (int): Um parâmetro que controla a inclinação da curva sigmoide. O valor padrão é 3. Valores maiores resultam em uma transição mais abrupta entre as pontuações baixas e altas.

        Retorna:
            float: A pontuação transformada em uma escala de 0 a 100.

        Exemplo:
            >>> sigmoid(0.5)
            50.0
            >>> sigmoid(0.25)
            11.920000000000002
            >>> sigmoid(0.75)
            88.08000000000001
    """

    return (1 / (1 + exp(-k * (weighted_average(scores, weights) - 0.5)))) * 100