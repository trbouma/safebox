ARG BASE_IMAGE=tiangolo/uvicorn-gunicorn-fastapi:python3.11
ARG LIBOQS_REF=0.14.0
ARG POETRY_VERSION=1.8.4

# ---------- build stage: compile liboqs ----------
FROM ${BASE_IMAGE} AS liboqs-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ninja-build \
    pkg-config \
    libssl-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN git clone --depth 1 --branch "${LIBOQS_REF}" https://github.com/open-quantum-safe/liboqs.git \
 && cmake -S liboqs -B liboqs/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=ON \
      -DOQS_ENABLE_SIG_STFL_LMS=ON \
      -DOQS_ENABLE_SIG_STFL_XMSS=ON \
      -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
 && cmake --build liboqs/build \
 && cmake --install liboqs/build

# ---------- runtime image ----------
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    POETRY_HOME=/opt/poetry \
    POETRY_VIRTUALENVS_CREATE=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/poetry/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    python3-dev \
    libpq-dev \
    build-essential \
    automake \
    pkg-config \
    libtool \
    libffi-dev \
    cmake \
    git \
    ca-certificates \
    openssl \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY --from=liboqs-builder /usr/local /usr/local
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig

RUN curl -sSL https://install.python-poetry.org | python3 - --version "${POETRY_VERSION}"

WORKDIR /app
COPY pyproject.toml poetry.lock /app/
RUN poetry install --only main --no-root --no-interaction
COPY . /app

RUN groupadd --system --gid 10001 appgroup \
 && useradd --system --uid 10001 --gid appgroup --create-home --home-dir /home/appuser appuser \
 && chown -R appuser:appgroup /app

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:7375/ >/dev/null || exit 1



