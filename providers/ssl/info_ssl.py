import ssl
import socket
import hashlib
import logging
from datetime import datetime, timezone
from providers.ssl.parse_issue_ssl import parse_issuer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID
from functools import lru_cache

logger = logging.getLogger("scanner.ssl")

def _public_key_algorithm(cert_obj: x509.Certificate) -> str | None:
    pub = cert_obj.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    return None


def _sig_algorithm(cert_obj: x509.Certificate) -> str | None:
    try:
        return (
            cert_obj.signature_hash_algorithm.name.upper()
            if cert_obj.signature_hash_algorithm
            else None
        )
    except Exception:
        return None


@lru_cache(maxsize=1)
def _verified_context():
    return ssl.create_default_context()


def get_ssl_cert(
    structure: dict, timeout: float = 3, resolved_ip: str | None = None
) -> dict:
    host = structure.get("hostname", "")

    if not host:
        return {}

    if structure.get("scheme") != "https":
        return {"enabled": False}
    ctx = _verified_context()

    try:
        with socket.create_connection(
            (resolved_ip or host, structure.get("port") or 443), timeout=timeout
        ) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_name, _, _ = ssock.cipher()
                ocsp_stapled = None

    except ConnectionRefusedError:
        logger.warning("%s error=connection_refused", host)
        return {"connection_error": True}

    except socket.timeout:
        logger.warning("%s error=timeout", host)
        return {"timeout": True}

    except ssl.SSLCertVerificationError:
        logger.warning("%s error=invalid_cert", host)
        return {"invalid_cert": True}

    except socket.gaierror:
        logger.warning("%s error=dns", host)
        return {"dns_error": True}

    except Exception:
        logger.warning("%s error=unknown", host)
        return {"unknown": True}

    cert_obj = x509.load_der_x509_certificate(cert_bin)

    issuer = {k: v for rdn in cert.get("issuer", []) for k, v in rdn}
    subject = {k: v for rdn in cert.get("subject", []) for k, v in rdn}

    san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    self_signed = cert.get("issuer") == cert.get("subject")

    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")

    try:
        dt_from = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        dt_until = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

        validity_days = (dt_until - dt_from).days
        valid_from = dt_from.strftime("%Y-%m-%d")
        valid_until = dt_until.strftime("%Y-%m-%d")

    except Exception:
        validity_days = None
        valid_from = not_before
        valid_until = not_after

    sha1 = hashlib.sha1(cert_bin).hexdigest().upper()
    sha256 = hashlib.sha256(cert_bin).hexdigest().upper()

    ocsp_reachable = None

    logger.info(
        "%s tls=%s cipher=%s issuer=%s san=%d valid_days=%s self_signed=%s ocsp_stapling=%s ocsp=%s",
        host,
        tls_version,
        cipher_name,
        issuer.get("organizationName") or issuer.get("commonName", ""),
        len(san),
        validity_days,
        self_signed,
        ocsp_stapled,
        ocsp_reachable,
    )

    return {
        "enabled": True,
        "hostname_valid": True,
        "chain_verified": True,
        "version": tls_version,
        "cipher_suite": cipher_name,
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "issuer_detail": issuer,
        "subject": subject.get("commonName", ""),
        "subject_detail": subject,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "validity_days": validity_days,
        "san": san,
        "san_count": len(san),
        "wildcard": any(s.startswith("*.") for s in san),
        "self_signed": self_signed,
        "serial_number": format(cert_obj.serial_number, "X"),
        "signature_algorithm": _sig_algorithm(cert_obj),
        "public_key_algorithm": _public_key_algorithm(cert_obj),
        "ocsp_stapling": ocsp_stapled,
        "ocsp_reachable": ocsp_reachable,
        "fingerprints": {"sha1": sha1, "sha256": sha256},
        "organization": subject.get("organizationName", ""),
    }
