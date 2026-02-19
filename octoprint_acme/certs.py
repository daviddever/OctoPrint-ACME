import datetime
import os
import tempfile

from cryptography import x509


def get_cert_info(cert_path):
    """
    Parse a PEM certificate file and return info dict.

    Returns:
        dict with keys: subject, issuer, not_before, not_after, days_remaining
    """
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data)
    now = datetime.datetime.now(datetime.timezone.utc)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_remaining": (cert.not_valid_after_utc - now).days,
    }


def combine_cert_key_for_haproxy(cert_path, key_path, output_path):
    """
    Create a combined PEM file for haproxy (cert chain + private key).

    Writes atomically via temp file + rename. Sets 0600 permissions.
    """
    with open(cert_path, "r") as cf:
        cert_data = cf.read()
    with open(key_path, "r") as kf:
        key_data = kf.read()

    combined = cert_data
    if not combined.endswith("\n"):
        combined += "\n"
    combined += key_data

    output_dir = os.path.dirname(output_path)
    fd, tmp_path = tempfile.mkstemp(dir=output_dir, prefix=".haproxy_pem_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(combined)
        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, output_path)
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
