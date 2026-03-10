FROM node:20-slim

# Install Python + system dependencies for Slither
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Slither via pip (break-system-packages for Debian 12+)
RUN pip3 install slither-analyzer --break-system-packages

# Install solc 0.8.20 static binary
RUN curl -Lo /usr/local/bin/solc \
    https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux \
    && chmod +x /usr/local/bin/solc

WORKDIR /app

# Install all dependencies (including devDeps for TypeScript build)
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Remove devDependencies after build
RUN npm prune --omit=dev

EXPOSE 8080
CMD ["node", "dist/index.js"]
