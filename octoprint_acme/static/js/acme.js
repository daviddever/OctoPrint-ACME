$(function () {
    function AcmeViewModel(parameters) {
        var self = this;
        self.settings = parameters[0];

        // Configuration
        self.fqdn = ko.observable("");
        self.email = ko.observable("");
        self.cloudflareToken = ko.observable("");
        self.tokenSet = ko.observable(false);

        // Validation
        self.validationResult = ko.observable(null);

        // lego status
        self.legoInstalled = ko.observable(false);
        self.legoVersion = ko.observable("");

        // Certificate status
        self.certInstalled = ko.observable(false);
        self.certFqdn = ko.observable("");
        self.certExpiry = ko.observable("");
        self.certIssuer = ko.observable("");
        self.certDaysRemaining = ko.observable(0);

        // haproxy status
        self.haproxyConfigured = ko.observable(false);
        self.haproxySslEnabled = ko.observable(false);

        // Working state
        self.working = ko.observable(false);
        self.workingMessage = ko.observable("");
        self.logOutput = ko.observableArray([]);

        // Computed
        self.certStatusClass = ko.pureComputed(function () {
            var days = self.certDaysRemaining();
            if (!self.certInstalled()) return "label-default";
            if (days > 30) return "label-success";
            if (days > 7) return "label-warning";
            return "label-danger";
        });

        self.canSave = ko.pureComputed(function () {
            return !self.working();
        });

        self.canIssue = ko.pureComputed(function () {
            return (
                self.fqdn() &&
                self.email() &&
                (self.tokenSet() || self.cloudflareToken()) &&
                self.legoInstalled() &&
                !self.working()
            );
        });

        self.canRenew = ko.pureComputed(function () {
            return self.certInstalled() && !self.working();
        });

        self.canConfigureHaproxy = ko.pureComputed(function () {
            return self.certInstalled() && !self.working();
        });

        // API helpers
        self._apiUrl = function (path) {
            return OctoPrint.getBlueprintUrl("acme") + "/" + path;
        };

        self._apiGet = function (path) {
            return OctoPrint.get(self._apiUrl(path));
        };

        self._apiPost = function (path, data) {
            return OctoPrint.postJson(self._apiUrl(path), data || {});
        };

        // Actions
        self.saveConfig = function () {
            var data = {
                plugins: {
                    acme: {
                        fqdn: self.fqdn(),
                        email: self.email()
                    }
                }
            };
            // Only send token if user entered a new one
            if (self.cloudflareToken()) {
                data.plugins.acme.cloudflare_api_token = self.cloudflareToken();
            }
            OctoPrint.settings.save(data).done(function () {
                self.cloudflareToken("");
                self.tokenSet(true);
                self.validationResult(null);
                self.refreshStatus();
            });
        };

        self.validateFqdn = function () {
            self.validationResult(null);
            self._apiPost("validate", {fqdn: self.fqdn()}).done(function (data) {
                self.validationResult(data);
            }).fail(function () {
                self.validationResult({valid: false, error: "Request failed"});
            });
        };

        self.installLego = function () {
            self.logOutput.removeAll();
            self._apiPost("lego/install").fail(function (xhr) {
                var msg = "Install request failed";
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    msg = xhr.responseJSON.error;
                }
                self.logOutput.push(msg);
            });
        };

        self.dryRun = function () {
            self.logOutput.removeAll();
            self._apiPost("issue", {dry_run: true}).fail(function (xhr) {
                var msg = "Dry run request failed";
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    msg = xhr.responseJSON.error;
                }
                self.logOutput.push(msg);
            });
        };

        self.issueCert = function () {
            self.logOutput.removeAll();
            self._apiPost("issue", {dry_run: false}).fail(function (xhr) {
                var msg = "Issue request failed";
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    msg = xhr.responseJSON.error;
                }
                self.logOutput.push(msg);
            });
        };

        self.renewCert = function () {
            self.logOutput.removeAll();
            self._apiPost("renew").fail(function (xhr) {
                var msg = "Renew request failed";
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    msg = xhr.responseJSON.error;
                }
                self.logOutput.push(msg);
            });
        };

        self.configureHaproxy = function () {
            showConfirmationDialog({
                title: "Generate haproxy setup script?",
                message:
                    "<p>This will generate a shell script that:</p>" +
                    "<ul>" +
                    "<li>Backs up <code>/etc/haproxy/haproxy.cfg</code></li>" +
                    "<li>Adds an HTTPS frontend on port 443</li>" +
                    "<li>Adds an HTTP &rarr; HTTPS redirect</li>" +
                    "<li>Restarts haproxy</li>" +
                    "</ul>" +
                    "<p>You will then need to run the script via SSH using <code>sudo</code>. The exact command will appear in the Activity Log.</p>",
                proceed: "Generate Script",
                onproceed: function () {
                    self.logOutput.removeAll();
                    self._apiPost("haproxy/configure").fail(function (xhr) {
                        var msg = "Configure request failed";
                        if (xhr.responseJSON && xhr.responseJSON.error) {
                            msg = xhr.responseJSON.error;
                        }
                        self.logOutput.push(msg);
                    });
                }
            });
        };

        self.clearLog = function () {
            self.logOutput.removeAll();
        };

        // Status refresh
        self.refreshStatus = function () {
            // Load settings
            var s = self.settings.settings;
            if (s && s.plugins && s.plugins.acme) {
                var acme = s.plugins.acme;
                self.fqdn(acme.fqdn());
                self.email(acme.email());
                self.tokenSet(acme.cloudflare_token_set ? acme.cloudflare_token_set() : false);
            }

            // lego status
            self._apiGet("lego/status").done(function (data) {
                self.legoInstalled(data.installed);
                self.legoVersion(data.version || "");
            });

            // Cert status
            self._apiGet("cert/status").done(function (data) {
                self.certInstalled(data.has_cert);
                if (data.has_cert) {
                    self.certFqdn(data.fqdn || "");
                    self.certExpiry(data.not_after || "");
                    self.certIssuer(data.issuer || "");
                    self.certDaysRemaining(data.days_remaining || 0);
                }
            });

            // haproxy status
            self._apiGet("haproxy/status").done(function (data) {
                self.haproxyConfigured(data.configured);
                self.haproxySslEnabled(data.ssl_enabled);
            });
        };

        // Plugin message handler
        self.onDataUpdaterPluginMessage = function (plugin, data) {
            if (plugin !== "acme") return;

            if (data.type === "log") {
                self.logOutput.push(data.line);
            } else if (data.type === "status") {
                self.working(data.working);
                if (data.message) {
                    self.workingMessage(data.message);
                }
            } else if (data.type === "result") {
                self.refreshStatus();
            }
        };

        // Lifecycle
        self.onSettingsShown = function () {
            self.refreshStatus();
        };

        self.onSettingsBeforeSave = function () {
            // Settings are saved explicitly via the Save Configuration button,
            // not via the global settings save.
        };
    }

    OCTOPRINT_VIEWMODELS.push({
        construct: AcmeViewModel,
        dependencies: ["settingsViewModel"],
        elements: ["#settings_plugin_acme"]
    });
});
