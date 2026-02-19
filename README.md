# OctoPrint-ACME

An OctoPrint plugin for obtaining and automatically renewing Let's Encrypt SSL certificates on OctoPi. Uses [lego](https://go-acme.github.io/lego/) as the ACME client with Cloudflare DNS-01 validation, and configures haproxy (OctoPi's built-in reverse proxy) to serve HTTPS.

## What It Does

- Issues single-FQDN SSL certificates from Let's Encrypt via Cloudflare DNS-01 challenge
- Automatically downloads and verifies the correct lego binary for your Pi's architecture
- Configures haproxy for HTTPS with automatic HTTP-to-HTTPS redirect
- Checks daily and auto-renews the certificate when it's within 30 days of expiring
- Keeps your private key and certificate files locked down with strict file permissions

## Prerequisites

Before installing the plugin, you need to set up two things yourself:

### 1. A Real Domain Name

Let's Encrypt cannot issue certificates for `.local` addresses (like `octopi.local`). You need a domain name with a DNS A record pointing to your OctoPi's IP address.

Your OctoPi does **not** need to be reachable from the internet. DNS-01 validation proves domain ownership through a DNS TXT record, so private/internal IPs (like `192.168.1.x`) work fine. The FQDN will only be usable on your local network in that case.

**Example:** If you own `example.com`, create an A record for `octoprint.example.com` pointing to `192.168.1.50` (your Pi's LAN IP).

### 2. A Cloudflare API Token

Your domain's DNS must be managed by Cloudflare (free plan is fine). Create an API token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with the following permission:

| Permission | Access |
| ---------- | ------ |
| Zone > DNS | Edit   |

Scope the token to only the zone (domain) you'll be using. The plugin uses this token to create the temporary TXT record that Let's Encrypt checks during DNS-01 validation.

### 3. OctoPi with haproxy

This plugin is designed for standard OctoPi images where haproxy sits in front of OctoPrint. Applying the haproxy configuration requires root access — see [Step 5: Enable HTTPS](#step-5-enable-https) for how this is handled.

## Installation

Install via the OctoPrint Plugin Manager using this URL:

```
https://github.com/daviddever/OctoPrint-ACME/releases/latest/download/OctoPrint-ACME.zip
```

Or install manually in OctoPrint's Python environment:

```bash
pip install https://github.com/daviddever/OctoPrint-ACME/releases/latest/download/OctoPrint-ACME.zip
```

Then restart OctoPrint.

## Usage

After installation, go to **Settings > ACME SSL**. The setup flow is:

### Step 1: Configure

- Enter your **FQDN** (e.g. `octoprint.example.com`) and click **Validate** to confirm DNS resolves
- Enter your **email address** (used for Let's Encrypt registration and expiry notifications)
- Enter your **Cloudflare API token**
- Click **Save Configuration**

### Step 2: Install lego

Click **Install lego**. The plugin detects your Pi's architecture (armv7, arm64, amd64, etc.), downloads the correct lego binary from GitHub, verifies its SHA256 checksum, and installs it to `~/.octoprint/acme/bin/lego`.

### Step 3: Test with a Dry Run

Click **Test (Dry Run)** to issue a test certificate from Let's Encrypt's staging server. This verifies that your Cloudflare token works and DNS-01 validation succeeds, without counting against Let's Encrypt's rate limits.

### Step 4: Issue a Real Certificate

Click **Issue Certificate** to obtain a production certificate. The certificate and private key are saved under `~/.octoprint/acme/certificates/`.

### Step 5: Enable HTTPS

Click **Configure haproxy & Enable HTTPS**. The plugin prepares everything it can without root access and generates a setup script:

1. Creates a combined PEM file at `~/.octoprint/ssl/haproxy.pem`
2. Generates an updated haproxy config with an HTTPS frontend (port 443) and an HTTP-to-HTTPS redirect
3. Writes the staged config and a setup script to `~/.octoprint/acme/configure-haproxy.sh`

The **Activity Log** will show the exact command to run. SSH into your OctoPi and run it:

```bash
sudo ~/.octoprint/acme/configure-haproxy.sh
```

The script will:

1. Create a timestamped backup of `/etc/haproxy/haproxy.cfg`
2. Install the new config
3. Validate it with `haproxy -c`
4. Restart haproxy

After it completes, reload the Settings page and click **Refresh Status** to confirm. Then access OctoPrint at `https://your-fqdn/`.

## Automatic Renewal

Once a certificate is issued, the plugin checks once per day whether the certificate is within 30 days of expiring. If so, it automatically:

1. Runs `lego renew` with the saved configuration
2. Rebuilds the combined PEM file for haproxy
3. Restarts haproxy to pick up the new certificate

No action is required from you. Renewal failures are logged and retried the next day.

## File Locations

| Path                                          | Purpose                                    | Permissions |
| --------------------------------------------- | ------------------------------------------ | ----------- |
| `~/.octoprint/acme/`                          | lego state and ACME account data           | `0700`      |
| `~/.octoprint/acme/bin/lego`                  | lego binary                                | `0755`      |
| `~/.octoprint/acme/certificates/`             | Certificates and keys (lego output)        |             |
| `~/.octoprint/acme/haproxy.cfg.staged`        | Generated haproxy config (pre-apply)       |             |
| `~/.octoprint/acme/configure-haproxy.sh`      | Setup script — run with `sudo` to apply    | `0755`      |
| `~/.octoprint/ssl/`                           | Combined PEM for haproxy                   | `0700`      |
| `~/.octoprint/ssl/haproxy.pem`                | Certificate chain + private key            | `0600`      |
| `/etc/haproxy/haproxy.cfg.bak.YYYYMMDDHHMMSS` | Timestamped backup created by setup script |             |

## Security Notes

- The Cloudflare API token is stored in OctoPrint's settings but is **never** returned through the REST API
- The token is automatically redacted from all log output
- Private key files are set to `0600` (owner read/write only)
- Certificate directories are set to `0700` (owner only)

## Limitations

- **Cloudflare DNS only** — only Cloudflare is supported as the DNS provider
- **Single FQDN only** — wildcard certificates are not supported
- **OctoPi/haproxy only** — designed for the standard OctoPi stack; other setups (nginx, direct Tornado SSL) are not supported
- **Linux only** — lego binaries are downloaded for Linux (which is what OctoPi runs)
