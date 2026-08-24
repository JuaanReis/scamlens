from time import time
from providers.http.http_result import HTTPResult
from plugins.scurl import __version__

def _typeError_request(status_code: int) -> tuple[str, str]:
    error_type, message = "", ""

    if status_code == 400:
        error_type = "invalid_request"
        message = "Solicitação inválida"

    elif status_code == 401:
        error_type = "unauthorized"
        message = "Autenticação necessária ou inválida"

    elif status_code == 403:
        error_type = "forbidden"
        message = "Acesso proibido"

    elif status_code == 404:
        error_type = "not_found"
        message = "Recurso não encontrado"

    elif status_code == 405:
        error_type = "method_not_allowed"
        message = "Método HTTP não permitido"

    elif status_code == 408:
        error_type = "timeout"
        message = "Tempo de requisição esgotado"

    elif status_code == 429:
        error_type = "rate_limited"
        message = "Muitas requisições"

    elif status_code == 500:
        error_type = "server_error"
        message = "Erro interno do servidor"

    elif status_code == 502:
        error_type = "bad_gateway"
        message = "Gateway inválido"

    elif status_code == 503:
        error_type = "service_unavailable"
        message = "Serviço indisponível"

    elif status_code == 504:
        error_type = "gateway_timeout"
        message = "Timeout no gateway"

    else:
        error_type = "unknown_error"
        message = f"Erro HTTP {status_code}"

    return error_type, message

def response_validator(response: HTTPResult, url: str, start: float) -> dict | None:
    if response is None:
        error_type = "Connection failure"
        message = "Site não respondeu ou DNS falhou"

    elif response.status >= 400:
        error_type, message = _typeError_request(response.status)

    else:
        error_type = None

    if error_type:
        return {
            "status": "error",
            "meta": {
                "url": url,
                "scan_time_s": round(time() - start, 3),
                "version": __version__
            },
            "error": {
                "type": error_type,
                "message": message
            }
        }
    
    else: 
        return None