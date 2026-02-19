import datetime
import logging
import os
import re
import shutil
import subprocess

logger = logging.getLogger("octoprint.plugins.acme.haproxy")

SSL_FRONTEND_TEMPLATE = """
frontend public_ssl
    bind *:443 ssl crt {pem_path}
    option forwardfor except 127.0.0.1
    http-request set-header X-Forwarded-Proto https
    use_backend webcam if {{ path_beg /webcam/ }}
    default_backend octoprint
"""

HTTPS_REDIRECT_LINE = "    redirect scheme https code 301 if !{ ssl_fc }"


def check_haproxy_ssl(cfg_path, pem_path=None):
    """
    Check if haproxy config has SSL configured with the plugin's certificate.

    If pem_path is provided, returns True only when the config references that
    specific PEM file, ignoring pre-existing certs such as the OctoPi snakeoil.
    """
    if not os.path.isfile(cfg_path):
        return False
    with open(cfg_path, "r") as f:
        content = f.read()
    has_ssl_bind = "ssl crt" in content and (
        "bind *:443" in content or "bind :::443" in content
    )
    if not has_ssl_bind:
        return False
    if pem_path is None:
        return True
    return pem_path in content


def backup_config(cfg_path):
    """Create a timestamped backup of haproxy.cfg. Returns backup path."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{cfg_path}.bak.{timestamp}"
    shutil.copy2(cfg_path, backup_path)
    logger.info("Created haproxy config backup at %s", backup_path)
    return backup_path


def generate_haproxy_config_content(current_content, pem_path):
    """
    Generate updated haproxy config content with SSL support.
    Does not write to disk.

    Strategy:
    1. If no SSL frontend exists, append one
    2. If SSL frontend exists, update the cert path
    3. Add HTTP->HTTPS redirect to port 80 frontend if not present

    Returns:
        (success: bool, new_content: str, message: str)
    """
    content = current_content

    if "bind *:443 ssl crt" not in content and "bind :::443 ssl crt" not in content:
        ssl_block = SSL_FRONTEND_TEMPLATE.format(pem_path=pem_path)
        content += "\n" + ssl_block
        logger.info("Added SSL frontend to haproxy config")
    else:
        content = re.sub(
            r"(bind [*:][:0-9]*443 ssl crt )\S+",
            rf"\g<1>{pem_path}",
            content,
        )
        logger.info("Updated cert path in existing SSL frontend")

    if "redirect scheme https" not in content:
        content = re.sub(
            r"(bind \*:80[^\n]*\n)",
            r"\g<1>" + HTTPS_REDIRECT_LINE + "\n",
            content,
            count=1,
        )
        logger.info("Added HTTPS redirect to port 80 frontend")

    if content == current_content:
        return True, content, "haproxy config already up to date"

    return True, content, "haproxy config prepared with SSL support"


_SETUP_SCRIPT_TEMPLATE = """\
#!/bin/bash
# OctoPrint ACME SSL — haproxy setup script
# Generated: {timestamp}
#
# Run with:  sudo {script_path}

set -e

CFG="{cfg_path}"
STAGED="{staged_cfg_path}"
BACKUP="{cfg_path}.bak.{timestamp}"

echo "[1/4] Backing up haproxy config to $BACKUP ..."
cp "$CFG" "$BACKUP"

echo "[2/4] Installing new haproxy config..."
cp "$STAGED" "$CFG"

echo "[3/4] Validating haproxy config..."
haproxy -c -f "$CFG"

echo "[4/4] Restarting haproxy..."
systemctl restart haproxy

echo ""
echo "Done! HTTPS is now configured."
echo "Return to OctoPrint settings and click Refresh Status."
"""


def write_setup_script(script_path, cfg_path, staged_cfg_path, pem_path, timestamp):
    """Write a shell script that applies the haproxy configuration with root privileges."""
    content = _SETUP_SCRIPT_TEMPLATE.format(
        timestamp=timestamp,
        script_path=script_path,
        cfg_path=cfg_path,
        staged_cfg_path=staged_cfg_path,
        pem_path=pem_path,
    )
    with open(script_path, "w") as f:
        f.write(content)
    logger.info("Wrote haproxy setup script to %s", script_path)


def validate_haproxy_config(cfg_path):
    """
    Validate haproxy config using haproxy -c.

    Returns:
        (valid: bool, output: str)
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "haproxy", "-c", "-f", cfg_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "haproxy config validation timed out"
    except OSError as e:
        return False, f"Failed to run haproxy validation: {e}"


def restart_haproxy():
    """
    Restart haproxy via systemctl.

    Returns:
        (success: bool, output: str)
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "haproxy"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            logger.info("haproxy restarted successfully")
        else:
            logger.error("Failed to restart haproxy: %s", output)
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "haproxy restart timed out"
    except OSError as e:
        return False, f"Failed to restart haproxy: {e}"
