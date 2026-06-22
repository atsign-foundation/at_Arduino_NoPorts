# =============================================================================
# NoPorts PoE – Firmware builder + web flasher (M5Stack Unit PoE-P4 / ESP32-P4)
#
# Build context must be the repo root so both lib/ and packages/NoPorts_PoE/
# are accessible:
#
#   docker build -f packages/NoPorts_PoE/Dockerfile -t noports-poe-flasher .
#
# Or use docker-compose (recommended):
#   docker compose -f packages/NoPorts_PoE/docker-compose.yml up --build
#
# NOTE: The first build downloads the pioarduino platform (~300 MB) and the
# ESP32-P4 RISC-V toolchain; subsequent builds use the Docker layer cache.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: build firmware
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir platformio esptool

WORKDIR /build

# ---------------------------------------------------------------------------
# Layer cache optimisation:
#   Copy only what's needed to fetch registry packages first, so rebuilds
#   that change only source code skip the slow platform/toolchain download.
# ---------------------------------------------------------------------------
COPY packages/NoPorts_PoE/platformio.ini      packages/NoPorts_PoE/platformio.ini
COPY packages/NoPorts_PoE/partitions_16mb.csv packages/NoPorts_PoE/partitions_16mb.csv
COPY packages/NoPorts_PoE/sdkconfig.defaults  packages/NoPorts_PoE/sdkconfig.defaults

# Stub so lib_extra_dirs (../../lib) resolves during pkg install without
# copying the full library yet (keeps this expensive layer cached).
RUN mkdir -p lib/NoPorts

WORKDIR /build/packages/NoPorts_PoE

# Download pioarduino platform, ESP32-P4 RISC-V toolchain, and registry libs.
# Cached unless platformio.ini changes.
RUN platformio pkg install -e esp32p4

# ---------------------------------------------------------------------------
# Now copy the full source and build
# ---------------------------------------------------------------------------
WORKDIR /build

COPY lib/                    lib/
COPY packages/NoPorts_PoE/   packages/NoPorts_PoE/

WORKDIR /build/packages/NoPorts_PoE

RUN platformio run -e esp32p4

# pioarduino generates firmware.factory.bin — a pre-merged image padded from
# 0x0 with bootloader at 0x2000 (ESP32-P4 / ESP-IDF 5.x offset).
# No manual esptool merge needed.
RUN BOOT=$(find /root/.platformio/packages -name "boot_app0.bin" | head -1) && \
    cp .pio/build/esp32p4/firmware.factory.bin merged-poe-p4.bin   && \
    cp .pio/build/esp32p4/firmware.bin         firmware-poe-p4.bin   && \
    cp .pio/build/esp32p4/partitions.bin       partitions-poe-p4.bin && \
    cp .pio/build/esp32p4/bootloader.bin       bootloader-poe-p4.bin && \
    cp "$BOOT" boot_app0.bin && \
    wc -c merged-poe-p4.bin firmware-poe-p4.bin partitions-poe-p4.bin \
              bootloader-poe-p4.bin boot_app0.bin

# ---------------------------------------------------------------------------
# Stage 2: minimal nginx web server
# ---------------------------------------------------------------------------
FROM nginx:1.28-alpine

RUN rm /etc/nginx/conf.d/default.conf
COPY packages/NoPorts_PoE/web/nginx.conf /etc/nginx/conf.d/noports.conf

COPY packages/NoPorts_PoE/web/ /usr/share/nginx/html/

COPY --from=builder /build/packages/NoPorts_PoE/merged-poe-p4.bin     /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_PoE/firmware-poe-p4.bin   /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_PoE/partitions-poe-p4.bin /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_PoE/bootloader-poe-p4.bin /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_PoE/boot_app0.bin          /usr/share/nginx/html/

EXPOSE 80

LABEL org.opencontainers.image.title="NoPorts PoE Flasher" \
      org.opencontainers.image.description="Browser-based firmware installer for NoPorts PoE (M5Stack Unit PoE-P4 / ESP32-P4)" \
      org.opencontainers.image.source="https://github.com/atsign-foundation/noports"
