# expmtl/Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps needed to build 'secp256k1' (monstr dependency)
# - build-essential: gcc, make, etc.
# - pkg-config: required by secp256k1 build
# - libsecp256k1-dev: native secp256k1 library headers
# - libssl-dev, libffi-dev: common crypto build deps (belt-and-suspenders)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libsecp256k1-dev libssl-dev libffi-dev \
  && rm -rf /var/lib/apt/lists/*

# Python deps
# Tip: switch to requirements.txt later if you prefer.
RUN pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir bech32 monstr pydantic pydantic-core pydantic-settings

# App
WORKDIR /app
COPY . /app

# Expose UDP 53 for DNS
EXPOSE 53/udp
EXPOSE 53/tcp

# Run your resolver
CMD ["python", "ns/npubresolver.py"]
