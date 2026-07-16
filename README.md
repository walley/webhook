# GitHub Webhook Listener in Rust

A lightweight, high-performance web server written in Rust using [Axum](https://github.com/tokio-rs/axum) that listens for GitHub webhooks and executes local bash scripts in response.

## Features
* **Secure**: HMAC-SHA256 signature verification (protects against unauthorized calls).
* **Asynchronous**: Executes bash scripts in the background using `tokio` without blocking the web server.
* **Extensible**: Easily map new GitHub events (`push`, `pull_request`, etc.) to specific scripts.
* **Low Footprint**: Minimal memory and CPU usage.

## Prerequisites
* [Rust](https://rustup.rs/) (latest stable version)
* `openssl` (required for HMAC verification)

## Setup

### 1. Configuration
The application relies on a secret environment variable to verify requests from GitHub.

```bash
# Set this in your environment or a .env file
export WEBHOOK_SECRET="your_very_secure_random_string"
```

### 2. Build
Clone the repository and compile the binary:

```bash
git clone https://github.com/walley/webhook.git
cd webhook
cargo build --release
```

The optimized binary will be located at `./target/release/github-webhook-listener`.

### 3. Scripts
The application expects scripts to be present in `/usr/local/bin/`. Ensure they are executable:

```bash
# Example for push events
sudo touch /usr/local/bin/github-push.sh
sudo chmod +x /usr/local/bin/github-push.sh
```

**Example `github-push.sh`:**
```bash
#!/bin/bash
echo "Push event received at $(date)" >> /var/log/webhook.log
# Your logic here, e.g., git pull or deploy
```

## Running the Service

### Development
```bash
WEBHOOK_SECRET=your_secret cargo run
```

### Production (systemd)
Create a file at `/etc/systemd/system/github-webhook.service`:

```ini
[Unit]
Description=GitHub Webhook Listener
After=network.target

[Service]
ExecStart=/path/to/your/binary/github-webhook-listener
Environment=WEBHOOK_SECRET=your_very_secure_random_string
Restart=always
User=your-user

[Install]
WantedBy=multi-user.target
```

Then enable and start it:
```bash
sudo systemctl enable github-webhook
sudo systemctl start github-webhook
```

## Security Notice
**Always** use a Webhook Secret. GitHub generates a signature using this secret, which allows our server to verify that the incoming payload is authentic and not a malicious request from an attacker. Ensure your secret is long, random, and not hardcoded in your source files.

## License
read LICENSE file very carefully



