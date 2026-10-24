import ipaddress
import socket
from scamLens import config

BLOCKED_RANGES = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.2.0/24",
    "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::ffff:0:0/96",
))

def _is_blocked_ip(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return _is_blocked_ip(ip.ipv4_mapped)
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
            or any(ip in network for network in BLOCKED_RANGES))

def address_block_reason(address):
    options = config["scurl"]["security"]
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (ip.is_loopback or ip.is_unspecified) and not options["allow_localhost"]:
        return "localhost"
    if _is_blocked_ip(ip) and not options["allow_private_ips"]:
        return "private_ip"
    return None

def resolve_and_validate_addresses(host):
    host = host.rstrip(".").lower()
    if not host or "%" in host:
        return "error", ()
    options = config["scurl"]["security"]
    if (host == "localhost" or host.endswith((".localhost", ".local"))) and not options["allow_localhost"]:
        return "localhost", ()
    try:
        addresses = (ipaddress.ip_address(host),)
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = tuple(dict.fromkeys(ipaddress.ip_address(answer[4][0]) for answer in answers))
        except (OSError, ValueError):
            return "error", ()
    if not addresses:
        return "error", ()
    for address in addresses:
        if reason := address_block_reason(address):
            return reason, ()
    return None, tuple(sorted(addresses, key=lambda address: address.version))

def resolve_and_validate_host(host):
    reason, addresses = resolve_and_validate_addresses(host)
    return reason, addresses[0] if addresses else None
