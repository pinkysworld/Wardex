# Installation Guide

## macOS (Homebrew)

```bash
brew tap pinkysworld/wardex
brew install wardex

# Start as a background service
brew services start wardex

# Or run manually
wardex serve 9077
```

The Homebrew tap is published from the dedicated repository `pinkysworld/homebrew-wardex`, so the standard commands now work without an explicit repository URL.

## Linux (Debian / Ubuntu)

Add the published APT repository and install with `apt-get`:

```bash
curl -fsSL https://pinkysworld.github.io/Wardex/apt/wardex-archive-key.asc \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/wardex-archive-keyring.gpg > /dev/null
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/wardex-archive-keyring.gpg] https://pinkysworld.github.io/Wardex/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/wardex.list > /dev/null
sudo apt-get update
sudo apt-get install wardex

# Enable and start the systemd service
sudo systemctl enable wardex
sudo systemctl start wardex
```

The APT repository is rebuilt from the latest published Debian release asset and served from GitHub Pages for this repository. If you need an offline or manual fallback, download the versioned `.deb` from the [latest release](https://github.com/pinkysworld/Wardex/releases/latest) and install it with `sudo dpkg -i ./wardex_<version>_amd64.deb`.

## Linux (RPM / Fedora / RHEL)

```bash
curl -LO https://github.com/pinkysworld/Wardex/releases/latest/download/wardex.x86_64.rpm
sudo rpm -i wardex.x86_64.rpm
sudo systemctl enable wardex
sudo systemctl start wardex
```

## Docker

```bash
docker pull ghcr.io/pinkysworld/wardex:latest

docker run -d \
  --name wardex \
  -p 9077:9077 \
  -v wardex-data:/app/var \
  ghcr.io/pinkysworld/wardex:latest
```

## Kubernetes (Helm)

```bash
helm repo add wardex https://pinkysworld.github.io/wardex-charts
helm repo update

helm install wardex wardex/wardex \
  --namespace wardex \
  --create-namespace \
  --set image.tag=0.56.1
```

Custom values:

```bash
helm install wardex wardex/wardex \
  --namespace wardex \
  --create-namespace \
  -f my-values.yaml
```

See `deploy/helm/wardex/values.yaml` for all configurable options.

## From Source

```bash
git clone https://github.com/pinkysworld/Wardex.git
cd Wardex
npm ci --prefix admin-console
cargo build --release
./target/release/wardex serve 9077
```

### Feature Flags

Disable experimental features at compile time:

```bash
# Minimal build (no ML, LLM, quantum, or proof modules)
cargo build --release --no-default-features

# Selective features
cargo build --release --no-default-features --features experimental-ml
```

## Verification

After installation, verify the service is running:

```bash
# Check version
wardex --version

# Health check
curl http://localhost:9077/api/healthz/ready

# Full status
curl http://localhost:9077/api/status-json
```

## SDK Installation

### Python

```bash
pip install wardex-sdk
```

### TypeScript / Node.js

```bash
npm install @wardex/sdk
```

To regenerate SDKs from the OpenAPI spec:

```bash
cd sdk && bash generate.sh
```
