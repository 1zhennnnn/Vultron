FROM python:3.11-slim

WORKDIR /app

# System deps: curl for solc download, git for slither
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install solc 0.8.20 static binary (covers ^0.8.x contracts)
RUN curl -fsSL https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux \
    -o /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App source
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
