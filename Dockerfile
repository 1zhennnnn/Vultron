FROM node:20-slim

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install slither-analyzer --break-system-packages

RUN curl -Lo /usr/local/bin/solc \
    https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux \
    && chmod +x /usr/local/bin/solc

WORKDIR /app

COPY backend/package*.json ./
RUN npm ci

COPY backend/ .
RUN npm run build
RUN npm prune --omit=dev

EXPOSE 3001
CMD ["node", "dist/index.js"]
