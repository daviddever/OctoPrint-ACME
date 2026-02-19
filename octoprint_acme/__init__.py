import datetime
import ipaddress
import logging
import os
import socket
import threading

import flask

import octoprint.plugin
from octoprint.access.permissions import Permissions
from octoprint.util import RepeatedTimer

from . import certs, haproxy, lego

RENEWAL_CHECK_INTERVAL = 86400  # 24 hours


class TokenRedactingFilter(logging.Filter):
    """Redact Cloudflare API tokens and other secrets from log output."""

    def __init__(self, tokens_getter):
        super().__init__()
        self._tokens_getter = tokens_getter

    def filter(self, record):
        tokens = self._tokens_getter()
        if isinstance(record.msg, str):
            for token in tokens:
                if token and len(token) > 8:
                    redacted = token[:4] + "****" + token[-4:]
                    record.msg = record.msg.replace(token, redacted)
            if record.args:
                new_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        for token in tokens:
                            if token and len(token) > 8:
                                redacted = token[:4] + "****" + token[-4:]
                                arg = arg.replace(token, redacted)
                    new_args.append(arg)
                record.args = tuple(new_args)
        return True


class AcmePlugin(
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.ShutdownPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
    octoprint.plugin.AssetPlugin,
    octoprint.plugin.BlueprintPlugin,
):
    def __init__(self):
        super().__init__()
        self._renewal_timer = None
        self._work_lock = threading.Lock()

    # ~~ Initialization

    def initialize(self):
        self._logger.addFilter(
            TokenRedactingFilter(
                lambda: [self._settings.get(["cloudflare_api_token"])]
            )
        )
        # Ensure directories exist with correct permissions
        self._ensure_directories()

    def _ensure_directories(self):
        ssl_dir = self._get_ssl_dir()
        acme_dir = self._get_acme_dir()
        for d in (ssl_dir, acme_dir):
            os.makedirs(d, mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)

    # ~~ Path helpers

    def _get_base_dir(self):
        return self._settings.global_get_basefolder("base")

    def _get_ssl_dir(self):
        return os.path.join(self._get_base_dir(), "ssl")

    def _get_acme_dir(self):
        return os.path.join(self._get_base_dir(), "acme")

    def _get_haproxy_pem_path(self):
        return os.path.join(self._get_ssl_dir(), "haproxy.pem")

    # ~~ Token redaction helper

    def _redact(self, text):
        token = self._settings.get(["cloudflare_api_token"])
        if token and len(token) > 8:
            text = text.replace(token, token[:4] + "****" + token[-4:])
        return text

    # ~~ Plugin message helper

    def _send_message(self, msg_type, **kwargs):
        data = {"type": msg_type}
        data.update(kwargs)
        self._plugin_manager.send_plugin_message(self._identifier, data)

    # ~~ StartupPlugin

    def on_after_startup(self):
        self._start_renewal_timer()

    # ~~ ShutdownPlugin

    def on_shutdown(self):
        if self._renewal_timer is not None:
            self._renewal_timer.cancel()

    # ~~ SettingsPlugin

    def get_settings_defaults(self):
        return {
            "fqdn": "",
            "email": "",
            "cloudflare_api_token": "",
            "lego_version": "4.31.0",
            "haproxy_cfg_path": "/etc/haproxy/haproxy.cfg",
            "renewal_days": 30,
            "cert_expiry": "",
            "last_issue_time": "",
            "last_renewal_time": "",
            "use_staging": False,
            "haproxy_configured": False,
        }

    def get_settings_restricted_paths(self):
        return {"never": [["cloudflare_api_token"]]}

    def on_settings_load(self):
        data = dict(octoprint.plugin.SettingsPlugin.on_settings_load(self))
        data["cloudflare_token_set"] = bool(
            self._settings.get(["cloudflare_api_token"])
        )
        data.pop("cloudflare_api_token", None)
        return data

    def on_settings_save(self, data):
        # Don't overwrite existing token with empty string
        if "cloudflare_api_token" in data and not data["cloudflare_api_token"]:
            del data["cloudflare_api_token"]
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)

    # ~~ TemplatePlugin

    def get_template_configs(self):
        return [{"type": "settings", "name": "ACME SSL", "custom_bindings": True}]

    # ~~ AssetPlugin

    def get_assets(self):
        return {"js": ["js/acme.js"], "css": ["css/acme.css"]}

    # ~~ BlueprintPlugin

    def is_blueprint_protected(self):
        return False

    def is_blueprint_csrf_protected(self):
        return True

    @octoprint.plugin.BlueprintPlugin.route("/validate", methods=["POST"])
    @Permissions.ADMIN.require(403)
    def validate_fqdn(self):
        data = flask.request.get_json(silent=True) or {}
        fqdn = data.get("fqdn", "").strip().lower()

        if not fqdn:
            return flask.jsonify({"valid": False, "error": "FQDN is required"})

        if "*" in fqdn:
            return flask.jsonify(
                {
                    "valid": False,
                    "error": "Wildcard domains are not supported. Use a single FQDN.",
                }
            )

        if fqdn.endswith(".local"):
            return flask.jsonify(
                {
                    "valid": False,
                    "error": (
                        "Cannot use .local domains (like octopi.local). "
                        "A real DNS name is required for Let's Encrypt certificates. "
                        "You need to register a domain and create a DNS A record "
                        "pointing to your OctoPi's IP address."
                    ),
                }
            )

        warnings = []

        try:
            ip = socket.gethostbyname(fqdn)
        except socket.gaierror:
            return flask.jsonify(
                {
                    "valid": False,
                    "error": (
                        f"DNS lookup failed for {fqdn}. "
                        "Make sure you have created a DNS A record for this domain."
                    ),
                }
            )

        try:
            if ipaddress.ip_address(ip).is_private:
                warnings.append(
                    f"Resolves to private IP {ip}. This is fine for DNS-01 "
                    "validation (no inbound port is needed), but this FQDN "
                    "will only be accessible on your local network."
                )
        except ValueError:
            pass

        return flask.jsonify({"valid": True, "ip": ip, "warnings": warnings})

    @octoprint.plugin.BlueprintPlugin.route("/lego/status", methods=["GET"])
    @Permissions.ADMIN.require(403)
    def lego_status(self):
        acme_dir = self._get_acme_dir()
        installed, version, path = lego.get_installed_version(acme_dir)
        return flask.jsonify(
            {"installed": installed, "version": version, "path": path}
        )

    @octoprint.plugin.BlueprintPlugin.route("/lego/install", methods=["POST"])
    @Permissions.ADMIN.require(403)
    def lego_install(self):
        if not self._work_lock.acquire(blocking=False):
            return flask.jsonify(
                {"success": False, "error": "Another operation is in progress"}
            )

        version = self._settings.get(["lego_version"])
        acme_dir = self._get_acme_dir()

        def do_install():
            try:
                self._send_message(
                    "status", working=True, message="Installing lego..."
                )

                def progress(msg):
                    self._send_message("log", line=msg)

                success, message = lego.download_and_install_lego(
                    version, acme_dir, progress_callback=progress
                )
                self._send_message("log", line=message)
                self._send_message("result", success=success, error="" if success else message)
            except Exception as e:
                self._logger.exception("Error installing lego")
                self._send_message("result", success=False, error=str(e))
            finally:
                self._send_message("status", working=False)
                self._work_lock.release()

        thread = threading.Thread(target=do_install, daemon=True)
        thread.start()
        return flask.jsonify({"started": True})

    @octoprint.plugin.BlueprintPlugin.route("/cert/status", methods=["GET"])
    @Permissions.ADMIN.require(403)
    def cert_status(self):
        fqdn = self._settings.get(["fqdn"])
        if not fqdn:
            return flask.jsonify({"has_cert": False})

        acme_dir = self._get_acme_dir()
        paths = lego.get_cert_paths(acme_dir, fqdn)

        if not os.path.isfile(paths["cert"]):
            return flask.jsonify({"has_cert": False})

        try:
            info = certs.get_cert_info(paths["cert"])
            return flask.jsonify(
                {
                    "has_cert": True,
                    "fqdn": fqdn,
                    "issuer": info["issuer"],
                    "not_after": info["not_after"],
                    "days_remaining": info["days_remaining"],
                }
            )
        except Exception as e:
            self._logger.exception("Error reading certificate")
            return flask.jsonify(
                {"has_cert": False, "error": str(e)}
            )

    @octoprint.plugin.BlueprintPlugin.route("/issue", methods=["POST"])
    @Permissions.ADMIN.require(403)
    def issue_certificate(self):
        if not self._work_lock.acquire(blocking=False):
            return flask.jsonify(
                {"success": False, "error": "Another operation is in progress"}
            )

        data = flask.request.get_json(silent=True) or {}
        dry_run = data.get("dry_run", False)

        def do_issue():
            try:
                self._do_issue(dry_run=dry_run)
            finally:
                self._work_lock.release()

        thread = threading.Thread(target=do_issue, daemon=True)
        thread.start()
        return flask.jsonify({"started": True})

    @octoprint.plugin.BlueprintPlugin.route("/renew", methods=["POST"])
    @Permissions.ADMIN.require(403)
    def renew_certificate(self):
        if not self._work_lock.acquire(blocking=False):
            return flask.jsonify(
                {"success": False, "error": "Another operation is in progress"}
            )

        def do_renew():
            try:
                self._do_renew()
            finally:
                self._work_lock.release()

        thread = threading.Thread(target=do_renew, daemon=True)
        thread.start()
        return flask.jsonify({"started": True})

    @octoprint.plugin.BlueprintPlugin.route("/haproxy/status", methods=["GET"])
    @Permissions.ADMIN.require(403)
    def haproxy_status(self):
        cfg_path = self._settings.get(["haproxy_cfg_path"])
        pem_path = self._get_haproxy_pem_path()
        has_ssl = haproxy.check_haproxy_ssl(cfg_path, pem_path)
        configured = self._settings.get_boolean(["haproxy_configured"])
        return flask.jsonify(
            {
                "configured": configured,
                "ssl_enabled": has_ssl,
                "cfg_path": cfg_path,
            }
        )

    @octoprint.plugin.BlueprintPlugin.route("/haproxy/configure", methods=["POST"])
    @Permissions.ADMIN.require(403)
    def configure_haproxy(self):
        if not self._work_lock.acquire(blocking=False):
            return flask.jsonify(
                {"success": False, "error": "Another operation is in progress"}
            )

        def do_configure():
            try:
                self._do_configure_haproxy()
            finally:
                self._work_lock.release()

        thread = threading.Thread(target=do_configure, daemon=True)
        thread.start()
        return flask.jsonify({"started": True})

    # ~~ Background operations

    def _do_issue(self, dry_run=False):
        action = "dry run" if dry_run else "issuance"
        try:
            self._send_message(
                "status", working=True, message=f"Starting certificate {action}..."
            )

            fqdn = self._settings.get(["fqdn"])
            email = self._settings.get(["email"])
            token = self._settings.get(["cloudflare_api_token"])

            if not fqdn:
                self._send_message("log", line="Error: FQDN not configured")
                self._send_message("result", success=False, error="FQDN not configured")
                return
            if not email:
                self._send_message("log", line="Error: Email not configured")
                self._send_message("result", success=False, error="Email not configured")
                return
            if not token:
                self._send_message(
                    "log", line="Error: Cloudflare API token not configured"
                )
                self._send_message(
                    "result",
                    success=False,
                    error="Cloudflare API token not configured",
                )
                return

            acme_dir = self._get_acme_dir()

            self._send_message(
                "log",
                line=f"Running lego for {fqdn} ({'staging' if dry_run else 'production'})...",
            )

            success, stdout, stderr = lego.run_lego(
                acme_dir=acme_dir,
                command="run",
                fqdn=fqdn,
                email=email,
                cloudflare_token=token,
                dry_run=dry_run,
            )

            # Log output (redacted)
            for line in (stdout + stderr).splitlines():
                line = line.strip()
                if line:
                    self._send_message("log", line=self._redact(line))

            if success:
                paths = lego.get_cert_paths(acme_dir, fqdn)
                # Set key permissions
                if os.path.isfile(paths["key"]):
                    os.chmod(paths["key"], 0o600)

                if not dry_run:
                    try:
                        info = certs.get_cert_info(paths["cert"])
                        self._settings.set(["cert_expiry"], info["not_after"])
                        self._settings.set(
                            ["last_issue_time"],
                            datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        )
                        self._settings.save()
                        self._send_message(
                            "log",
                            line=f"Certificate issued successfully! Expires: {info['not_after']} ({info['days_remaining']} days)",
                        )
                    except Exception:
                        self._logger.exception("Error reading issued certificate")
                        self._send_message(
                            "log", line="Certificate issued but could not read cert info"
                        )
                else:
                    self._send_message(
                        "log", line="Dry run completed successfully!"
                    )
                self._send_message("result", success=True)
            else:
                self._send_message("log", line=f"Certificate {action} FAILED")
                self._send_message(
                    "result", success=False, error=self._redact(stderr)
                )
        except Exception as e:
            self._logger.exception("Error during certificate %s", action)
            self._send_message("result", success=False, error=str(e))
        finally:
            self._send_message("status", working=False)

    def _do_renew(self):
        try:
            self._send_message(
                "status", working=True, message="Renewing certificate..."
            )

            fqdn = self._settings.get(["fqdn"])
            email = self._settings.get(["email"])
            token = self._settings.get(["cloudflare_api_token"])
            acme_dir = self._get_acme_dir()

            if not all([fqdn, email, token]):
                self._send_message(
                    "log", line="Error: Missing configuration (FQDN, email, or token)"
                )
                self._send_message(
                    "result", success=False, error="Missing configuration"
                )
                return

            self._send_message("log", line=f"Renewing certificate for {fqdn}...")

            success, stdout, stderr = lego.run_lego(
                acme_dir=acme_dir,
                command="renew",
                fqdn=fqdn,
                email=email,
                cloudflare_token=token,
                dry_run=False,
            )

            for line in (stdout + stderr).splitlines():
                line = line.strip()
                if line:
                    self._send_message("log", line=self._redact(line))

            if success:
                paths = lego.get_cert_paths(acme_dir, fqdn)
                if os.path.isfile(paths["key"]):
                    os.chmod(paths["key"], 0o600)

                try:
                    info = certs.get_cert_info(paths["cert"])
                    self._settings.set(["cert_expiry"], info["not_after"])
                    self._settings.set(
                        ["last_renewal_time"],
                        datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    )
                    self._settings.save()
                    self._send_message(
                        "log",
                        line=f"Certificate renewed! Expires: {info['not_after']} ({info['days_remaining']} days)",
                    )
                except Exception:
                    self._logger.exception("Error reading renewed certificate")

                # Update haproxy PEM if configured
                if self._settings.get_boolean(["haproxy_configured"]):
                    self._update_haproxy_pem(fqdn, acme_dir)

                self._send_message("result", success=True)
            else:
                self._send_message("log", line="Certificate renewal FAILED")
                self._send_message(
                    "result", success=False, error=self._redact(stderr)
                )
        except Exception as e:
            self._logger.exception("Error during certificate renewal")
            self._send_message("result", success=False, error=str(e))
        finally:
            self._send_message("status", working=False)

    def _update_haproxy_pem(self, fqdn, acme_dir):
        """Re-combine cert+key PEM and restart haproxy."""
        paths = lego.get_cert_paths(acme_dir, fqdn)
        pem_path = self._get_haproxy_pem_path()
        try:
            certs.combine_cert_key_for_haproxy(
                paths["cert"], paths["key"], pem_path
            )
            self._send_message("log", line="Updated haproxy PEM file")
            ok, output = haproxy.restart_haproxy()
            if ok:
                self._send_message("log", line="haproxy restarted successfully")
            else:
                self._send_message(
                    "log", line=f"Warning: haproxy restart failed: {output}"
                )
        except Exception:
            self._logger.exception("Error updating haproxy PEM")
            self._send_message(
                "log", line="Warning: Failed to update haproxy PEM"
            )

    def _do_configure_haproxy(self):
        try:
            self._send_message(
                "status", working=True, message="Preparing haproxy setup script..."
            )

            fqdn = self._settings.get(["fqdn"])
            acme_dir = self._get_acme_dir()
            cfg_path = self._settings.get(["haproxy_cfg_path"])
            pem_path = self._get_haproxy_pem_path()

            if not fqdn:
                self._send_message("result", success=False, error="FQDN not configured")
                return

            paths = lego.get_cert_paths(acme_dir, fqdn)
            if not os.path.isfile(paths["cert"]) or not os.path.isfile(paths["key"]):
                self._send_message(
                    "result",
                    success=False,
                    error="Certificate not found. Issue a certificate first.",
                )
                return

            if not os.path.isfile(cfg_path):
                self._send_message(
                    "result",
                    success=False,
                    error=f"haproxy config not found at {cfg_path}",
                )
                return

            # Combine cert + key into PEM (writes to ~/.octoprint/ssl/ — no sudo needed)
            self._send_message("log", line="Creating combined PEM file for haproxy...")
            certs.combine_cert_key_for_haproxy(paths["cert"], paths["key"], pem_path)

            # Read the current haproxy config (world-readable — no sudo needed)
            with open(cfg_path, "r") as f:
                current_content = f.read()

            # Generate the updated config content (no disk writes yet)
            ok, new_content, msg = haproxy.generate_haproxy_config_content(
                current_content, pem_path
            )
            if not ok:
                self._send_message("result", success=False, error=msg)
                return
            self._send_message("log", line=msg)

            # Write staged config and setup script into acme_dir (no sudo needed)
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            staged_cfg_path = os.path.join(acme_dir, "haproxy.cfg.staged")
            script_path = os.path.join(acme_dir, "configure-haproxy.sh")

            with open(staged_cfg_path, "w") as f:
                f.write(new_content)

            haproxy.write_setup_script(
                script_path, cfg_path, staged_cfg_path, pem_path, timestamp
            )
            os.chmod(script_path, 0o755)

            self._send_message("log", line="Setup script written. Run via SSH to apply:")
            self._send_message("log", line=f"  sudo {script_path}")
            self._send_message(
                "log",
                line="Then reload this settings page and click Refresh Status.",
            )
            self._send_message("result", success=True)
        except Exception as e:
            self._logger.exception("Error preparing haproxy setup")
            self._send_message("result", success=False, error=str(e))
        finally:
            self._send_message("status", working=False)

    # ~~ Renewal timer

    def _start_renewal_timer(self):
        self._renewal_timer = RepeatedTimer(
            RENEWAL_CHECK_INTERVAL,
            self._check_renewal,
            run_first=True,
        )
        self._renewal_timer.start()

    def _check_renewal(self):
        fqdn = self._settings.get(["fqdn"])
        if not fqdn:
            return

        acme_dir = self._get_acme_dir()
        paths = lego.get_cert_paths(acme_dir, fqdn)

        if not os.path.isfile(paths["cert"]):
            return

        try:
            info = certs.get_cert_info(paths["cert"])
            days = info["days_remaining"]
            renewal_days = self._settings.get_int(["renewal_days"])

            if days <= renewal_days:
                self._logger.info(
                    "Certificate expires in %d days (threshold: %d), attempting renewal",
                    days,
                    renewal_days,
                )
                if self._work_lock.acquire(blocking=False):
                    try:
                        self._do_renew()
                    finally:
                        self._work_lock.release()
                else:
                    self._logger.info(
                        "Skipping auto-renewal, another operation is in progress"
                    )
            else:
                self._logger.debug(
                    "Certificate OK, %d days remaining", days
                )
        except Exception:
            self._logger.exception("Error checking certificate renewal")


# ~~ Plugin registration

__plugin_name__ = "ACME SSL"
__plugin_pythoncompat__ = ">=3.9,<4"
__plugin_implementation__ = None


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = AcmePlugin()
