"""Heurísticas de geometry. Registro por importação explícita."""
from . import too_many_identical_neighbors
from . import suspicious_repeated_rows
from . import suspicious_repeated_columns
from . import repeated_small_tiles
from . import extreme_horizontal_symmetry
from . import extreme_vertical_symmetry
from . import directional_gradient_imbalance
from . import stripe_row_irregularity
from . import stripe_column_irregularity
