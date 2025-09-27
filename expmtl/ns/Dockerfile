# expmtl/Dockerfile
FROM python:3.12-slim

# System setup
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install runtime deps (adjust as needed)
# - bech32: for npub decoding (import bech32)
# - monstr: Nostr client lib
RUN pip install --no-cache-dir bech32 monstr

# Copy app
WORKDIR /app
COPY . /app

# Expose DNS (UDP). We only expose UDP since the server is UDP-only.
EXPOSE 53/udp

# Default command: run your resolver
CMD ["python", "ns/npubresolver.py"]
