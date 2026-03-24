FROM node:20-slim AS base

# Install Python 3 + pip for Python language pack sidecars
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install gitleaks (MIT)
ARG GITLEAKS_VERSION=8.18.4
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# Install osv-scanner (Apache 2.0)
ARG OSV_SCANNER_VERSION=1.8.3
RUN curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# Install Python analysis tools
RUN pip3 install --break-system-packages --no-cache-dir \
    lizard \
    bandit \
    pip-audit \
    pytest \
    pytest-cov

WORKDIR /action

# Copy package manifests and install Node deps
COPY package.json package-lock.json ./
RUN npm ci --production

# Copy action source
COPY dist/ dist/
COPY action.yml .
COPY language-packs/ language-packs/

ENTRYPOINT ["node", "/action/dist/index.js"]
