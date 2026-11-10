FROM ubuntu:24.04

LABEL org.opencontainers.image.title="dfirbaboon-worker"
LABEL org.opencontainers.image.description="Serverless Cloud-Native DFIR Pipeline Worker (The Sleuth Kit, YARA, Chain of Custody, AI Markdown Exporter)"
LABEL org.opencontainers.image.source="https://github.com/awfullyniceguy/dfirbaboon"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WORK_DIR=/tmp/work

# Install essential forensic binaries, dev libraries, and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit \
    ewf-tools \
    afflib-tools \
    yara \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libtsk-dev \
    libyara-dev \
    pkg-config \
    jq \
    file \
    testdisk \
    libimage-exiftool-perl \
    binutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Hardening: Remove setuid and setgid bits from binaries to prevent privilege escalation
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Hardening: Create unprivileged system group and user
RUN groupadd -g 10001 dfirgroup && \
    useradd -u 10001 -g dfirgroup -m -s /bin/sh dfirworker

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /app/requirements.txt

COPY config.py /app/config.py
COPY parsers/ /app/parsers/
COPY rules/ /app/rules/
COPY entrypoint.py /app/entrypoint.py

# Create workspace directory with correct ownership and permissions
RUN mkdir -p /tmp/work && \
    chown -R dfirworker:dfirgroup /app /tmp/work && \
    chmod 755 /app/entrypoint.py

# Run as non-root unprivileged user
USER dfirworker:dfirgroup

ENTRYPOINT ["python3", "/app/entrypoint.py"]
