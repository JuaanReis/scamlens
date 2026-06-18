import ssl
import socket
import hashlib
from datetime import datetime, timezone
from plugins.scurl.parsers.parse_issue_ssl import parse_issuer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID
import urllib.request

def _check_ocsp_stapling(ssock: ssl.SSLSocket) -> bool | None:
    try:
        if ssock.version() == "TLSv1.3":
            return None
        response = ssock.get_channel_binding("tls-unique")
        return response is not None
    except Exception:
        return None

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
        return cert_obj.signature_hash_algorithm.name.upper() if cert_obj.signature_hash_algorithm else None
    except Exception:
        return None

def _ocsp_url(cert_obj: x509.Certificate) -> str | None:
    try:
        aia = cert_obj.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access in aia.value:
            if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":  
                return access.access_location.value
    except Exception:
        return None

def _verify_ocsp(cert_obj: x509.Certificate, issuer_cert_bin: bytes | None = None) -> bool | None:
    ocsp_url = _ocsp_url(cert_obj)
    if not ocsp_url:
        return None
    try:
        req = urllib.request.Request(ocsp_url, method="HEAD")
        req.add_header("User-Agent", "scurl/1.0")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status < 400
    except Exception:
        return None

def get_ssl_cert(structure: dict) -> dict:
    host = structure.get("hostname", "")
    if not host:
        return {}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL

    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_name, _, _ = ssock.cipher()
                ocsp_stapled = _check_ocsp_stapling(ssock)

    except ConnectionRefusedError:
        return {"connection_error": True}
    except socket.timeout:
        return {"timeout": True}
    except ssl.SSLCertVerificationError:
        return {"invalid_cert": True}
    except socket.gaierror:
        return {"dns_error": True}
    except Exception:
        return {"unknown": True}

    cert_obj = x509.load_der_x509_certificate(cert_bin)
    issuer = parse_issuer(cert.get("issuer", []))
    subject = parse_issuer(cert.get("subject", []))
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

    ocsp_reachable = _verify_ocsp(cert_obj)

    return {
        "enabled": True,
        "version": tls_version,
        "cipher_suite": cipher_name,
        "issuer": issuer.get("O") or issuer.get("CN", ""),
        "issuer_detail": issuer,
        "subject": subject.get("CN", ""),
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
        "fingerprints": {
            "sha1": sha1,
            "sha256": sha256
        },
        "organization": subject.get("O", "")
    }