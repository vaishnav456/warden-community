# Cross-compiling agent-go (pure Go, no cgo, no Windows-only resource
# embedding — see agent-go/go.mod) needs nothing but the Go toolchain, so
# this runs as a plain Linux container instead of requiring its own
# dedicated Windows build machine (the old PyInstaller-based path did).
FROM golang:1.27.1-bookworm AS go-toolchain

# The full Go image contains C/C++ compilers and build-essential libraries
# that this CGO-disabled cross compiler does not need. Keep only the Go
# toolchain in the smaller runtime instead of exposing the entire SDK image.
FROM python:3.12-slim
COPY --from=go-toolchain /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# osslsigncode: Authenticode-signs the built exe from a PFX cert without
# needing Windows/signtool.exe at all — see builder.py's sign_binary().
# msitools (wixl): compiles WiX-syntax XML into a real .msi natively on
# Linux — no Windows/.NET/WiX Toolset needed. Used for the domain-deployment
# packaging (GPO Software Installation, SCCM, Intune Win32 apps all require
# .msi specifically, not a raw .exe/.bat) — see builder.py's build_msi().
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    osslsigncode openssl wixl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10002 warden-build \
    && useradd --system --uid 10002 --gid warden-build --home-dir /app --shell /usr/sbin/nologin warden-build

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY --chown=warden-build:warden-build . .

RUN mkdir -p /build-output /tmp/gocache /tmp/gopath \
    && chown -R warden-build:warden-build /app /build-output /tmp/gocache /tmp/gopath

ENV GOCACHE=/tmp/gocache
ENV GOPATH=/tmp/gopath
ENV PYTHONDONTWRITEBYTECODE=1

USER 10002:10002

CMD ["python3", "build_agent.py"]
