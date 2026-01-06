# ---------- build stage: compile liboqs ----------
FROM python:3.11-slim  AS liboqs-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ninja-build \
    pkg-config \
    libssl-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

WORKDIR /tmp

# Pin to a known-good commit or tag for reproducibility (optional but recommended)
ARG LIBOQS_REF=main

RUN git clone https://github.com/open-quantum-safe/liboqs.git \
 && cd liboqs \
 && git checkout "${LIBOQS_REF}" \
 && cmake -S . -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=ON \
      -DOQS_ENABLE_SIG_STFL_LMS=ON \
      -DOQS_ENABLE_SIG_STFL_XMSS=ON \
      -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
 && cmake --build build \
 && cmake --install build

FROM python:3.11-slim 
RUN apt-get update
RUN apt-get install -y curl python3-dev autoconf g++
RUN apt-get install -y libpq-dev

# Deps for building secp256k1-py
RUN apt-get install -y build-essential automake pkg-config libtool libffi-dev

RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*


RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

COPY --from=liboqs-builder /usr/local /usr/local
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig

WORKDIR /app
COPY . .
RUN poetry config virtualenvs.create false
RUN poetry install --only main --no-root
