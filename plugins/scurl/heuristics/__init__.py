"""
Módulo de agregação de componentes de análise.

Este arquivo centraliza a importação de diferentes módulos responsáveis pela avaliação estrutural e comportamental de URLs e recursos associados. Ele atua como ponto de composição do sistema de análise, reunindo verificações aplicadas em múltiplas camadas, incluindo estrutura de URL, comportamento do conteúdo, propriedades do domínio e características do servidor.

A arquitetura do sistema é modular, permitindo que cada componente seja mantido e evoluído de forma independente, ao mesmo tempo em que contribui para uma análise unificada. Essa abordagem facilita escalabilidade, testes isolados e a adição de novos mecanismos de avaliação sem impacto direto no fluxo principal.

Os módulos importados são utilizados durante o processo de inspeção para compor um perfil geral de risco, combinando diferentes sinais coletados ao longo da análise. O objetivo é fornecer uma visão consolidada e consistente do comportamento observado, permitindo classificações mais precisas e adaptáveis a diferentes cenários de ameaça.

Este arquivo não executa lógica de análise diretamente, funcionando apenas como ponto de integração entre os componentes do sistema.
"""

from plugins.scurl.heuristics.html import image_check, inline_data_css, missing_form_tag, password_input
from plugins.scurl.heuristics.server import domain_age
from plugins.scurl.heuristics.url import character
from plugins.scurl.heuristics.url import parts
from plugins.scurl.heuristics.html import redirect_check
from plugins.scurl.heuristics.server import rdap_field
from plugins.scurl.heuristics.server.dns_verify import dns_verify
from plugins.scurl.heuristics.server.ssl_verify import ssl_verify
from plugins.scurl.heuristics.html import script_integrity_absent
from plugins.scurl.heuristics.server import nameserver_diversity
from plugins.scurl.heuristics.url import domain
from plugins.scurl.heuristics.url.typos import typosquatting
from plugins.scurl.heuristics.server import safe_browsing
from plugins.scurl.heuristics.html import clients_hint, external_script, favicon_check, form_action, hidden_fields
from plugins.scurl.heuristics.html import credential_signals
from plugins.scurl.heuristics.url import deception
from plugins.scurl.heuristics.url.base64_detect import base64_segments
