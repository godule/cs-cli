"""Self-signed TLS certificate generation (stdlib: ssl + openssl via subprocess
fallback). Used to wrap a listener with HTTPS.
"""
import datetime
import hashlib
import ipaddress
import os
import socket
import subprocess
import tempfile


def _get_public_ip():
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            continue
    return "127.0.0.1"


def generate_self_signed_cert(cert_path, key_path, common_name=None, alt_ips=None):
    """Generate a self-signed cert + key (RSA 2048) using the `openssl` CLI if
    available, else fall back to pure-python via `ssl` (limited). Returns the
    paths."""
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    if common_name is None:
        common_name = _get_public_ip()
    alt_names = []
    for ip in ([common_name] + (alt_ips or [])):
        try:
            ipaddress.ip_address(ip)
            alt_names.append(f"IP:{ip}")
        except ValueError:
            alt_names.append(f"DNS:{ip}")
    san = ",".join(alt_names) or f"IP:{common_name}"

    if _have_openssl():
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
            f.write(_config_text(common_name, san))
            cnf = f.name
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                 "-keyout", key_path, "-out", cert_path, "-days", "825",
                 "-nodes", "-subj", f"/CN={common_name}",
                 "-extensions", "v3_req", "-config", cnf],
                check=True, capture_output=True, timeout=90)
            os.unlink(cnf)
            return cert_path, key_path
        except Exception:
            if os.path.exists(cnf):
                os.unlink(cnf)
    # Fallback: very small pure-python path won't produce a *trusted* cert, so
    # raise clearly. OpenSSL is available in most Linux distros.
    raise RuntimeError("openssl CLI required to generate a TLS certificate")


def _have_openssl():
    from shutil import which
    return which("openssl") is not None


def _config_text(cn, san):
    return f"""[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = {cn}

[v3_req]
subjectAltName = {san}
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
"""
