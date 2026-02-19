import hashlib
import logging
import os
import platform
import subprocess
import tarfile
import tempfile

import requests

logger = logging.getLogger("octoprint.plugins.acme.lego")

ARCH_MAP = {
    "x86_64": "amd64",
    "aarch64": "arm64",
    "armv7l": "armv7",
    "armv6l": "armv6",
}

GITHUB_RELEASE_URL = (
    "https://github.com/go-acme/lego/releases/download/v{version}/{filename}"
)

LE_STAGING_SERVER = (
    "https://acme-staging-v02.api.letsencrypt.org/directory"
)


def get_lego_arch():
    """Return (os_name, arch) tuple for lego download filename."""
    machine = platform.machine().lower()
    arch = ARCH_MAP.get(machine)
    if arch is None:
        raise ValueError(
            f"Unsupported architecture: {machine}. "
            f"Supported: {', '.join(ARCH_MAP.keys())}"
        )
    return ("linux", arch)


def get_lego_filename(version):
    """Return the tarball filename for the current platform."""
    os_name, arch = get_lego_arch()
    return f"lego_v{version}_{os_name}_{arch}.tar.gz"


def _download_file(url, dest_path, progress_callback=None):
    """Download a file from url to dest_path."""
    response = requests.get(url, stream=True, timeout=120)
    response.raise_for_status()

    total = int(response.headers.get("content-length", 0))
    downloaded = 0

    with open(dest_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
            downloaded += len(chunk)
            if progress_callback and total > 0:
                progress_callback(downloaded, total)


def _compute_sha256(file_path):
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _parse_checksums(checksums_text, target_filename):
    """Parse a checksums.txt file and return the hash for the target filename."""
    for line in checksums_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == target_filename:
            return parts[0]
    return None


def download_and_install_lego(version, acme_dir, progress_callback=None):
    """
    Download lego binary, verify checksum, and install to acme_dir/bin/lego.

    Args:
        version: lego version string (e.g. "4.21.0")
        acme_dir: Path to ~/.octoprint/acme/
        progress_callback: Optional callable(message_str)

    Returns:
        (success, message)
    """
    filename = get_lego_filename(version)
    checksums_filename = f"lego_{version}_checksums.txt"

    tarball_url = GITHUB_RELEASE_URL.format(version=version, filename=filename)
    checksums_url = GITHUB_RELEASE_URL.format(
        version=version, filename=checksums_filename
    )

    bin_dir = os.path.join(acme_dir, "bin")
    os.makedirs(bin_dir, mode=0o700, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Download checksums
        if progress_callback:
            progress_callback("Downloading checksums...")
        checksums_path = os.path.join(tmp_dir, checksums_filename)
        try:
            _download_file(checksums_url, checksums_path)
        except requests.RequestException as e:
            return False, f"Failed to download checksums: {e}"

        with open(checksums_path, "r") as f:
            checksums_text = f.read()

        expected_hash = _parse_checksums(checksums_text, filename)
        if expected_hash is None:
            return False, (
                f"Could not find checksum for {filename} in checksums file"
            )

        # Download tarball
        if progress_callback:
            progress_callback(f"Downloading {filename}...")
        tarball_path = os.path.join(tmp_dir, filename)
        try:
            _download_file(tarball_url, tarball_path)
        except requests.RequestException as e:
            return False, f"Failed to download lego: {e}"

        # Verify checksum
        if progress_callback:
            progress_callback("Verifying checksum...")
        actual_hash = _compute_sha256(tarball_path)
        if actual_hash != expected_hash:
            return False, (
                f"Checksum mismatch! Expected {expected_hash}, "
                f"got {actual_hash}. The download may be corrupted."
            )

        # Extract lego binary
        if progress_callback:
            progress_callback("Extracting lego binary...")
        try:
            with tarfile.open(tarball_path, "r:gz") as tar:
                # Only extract the lego binary
                members = [m for m in tar.getmembers() if m.name == "lego"]
                if not members:
                    return False, "lego binary not found in archive"
                tar.extract(members[0], path=tmp_dir)
        except tarfile.TarError as e:
            return False, f"Failed to extract archive: {e}"

        # Move to final location
        extracted_path = os.path.join(tmp_dir, "lego")
        dest_path = os.path.join(bin_dir, "lego")
        # Use copy + remove for cross-device moves
        import shutil

        shutil.copy2(extracted_path, dest_path)
        os.chmod(dest_path, 0o755)

    if progress_callback:
        progress_callback(f"lego v{version} installed successfully")
    return True, f"lego v{version} installed to {dest_path}"


def get_installed_version(acme_dir):
    """
    Get the version of the installed lego binary, or None if not installed.

    Returns:
        (installed: bool, version: str or None, path: str)
    """
    lego_bin = os.path.join(acme_dir, "bin", "lego")
    if not os.path.isfile(lego_bin):
        return False, None, lego_bin

    try:
        result = subprocess.run(
            [lego_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # lego --version outputs something like "lego version 4.21.0 linux/arm64"
        version_str = result.stdout.strip()
        # Extract version number
        parts = version_str.split()
        for i, part in enumerate(parts):
            if part == "version" and i + 1 < len(parts):
                return True, parts[i + 1], lego_bin
        return True, version_str, lego_bin
    except (subprocess.SubprocessError, OSError):
        return True, "unknown", lego_bin


def run_lego(acme_dir, command, fqdn, email, cloudflare_token, dry_run=False):
    """
    Execute lego to issue or renew a certificate.

    Args:
        acme_dir: Path to ~/.octoprint/acme/ (used as --path)
        command: "run" (initial issue) or "renew"
        fqdn: The domain name
        email: ACME registration email
        cloudflare_token: Cloudflare API token
        dry_run: If True, use LE staging server

    Returns:
        (success: bool, stdout: str, stderr: str)
    """
    lego_bin = os.path.join(acme_dir, "bin", "lego")
    if not os.path.isfile(lego_bin):
        return False, "", "lego binary not found. Please install lego first."

    cmd = [
        lego_bin,
        "--path", acme_dir,
        "--email", email,
        "--domains", fqdn,
        "--dns", "cloudflare",
        "--dns.resolvers", "1.1.1.1:53,8.8.8.8:53",
        "--accept-tos",
    ]

    if dry_run:
        cmd.extend(["--server", LE_STAGING_SERVER])

    if command == "run":
        cmd.append("run")
    elif command == "renew":
        cmd.extend(["renew", "--days", "30", "--no-random-sleep"])
    else:
        return False, "", f"Unknown command: {command}"

    env = os.environ.copy()
    env["CLOUDFLARE_DNS_API_TOKEN"] = cloudflare_token

    logger.info("Running lego %s for %s (dry_run=%s)", command, fqdn, dry_run)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "lego command timed out after 5 minutes"
    except OSError as e:
        return False, "", f"Failed to execute lego: {e}"


def get_cert_paths(acme_dir, fqdn):
    """Return the paths where lego stores cert and key."""
    certs_dir = os.path.join(acme_dir, "certificates")
    return {
        "cert": os.path.join(certs_dir, f"{fqdn}.crt"),
        "key": os.path.join(certs_dir, f"{fqdn}.key"),
    }
