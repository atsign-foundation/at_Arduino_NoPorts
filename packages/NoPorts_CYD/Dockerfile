# =============================================================================
# NoPorts CYD – Firmware builder + web flasher
#
# Build context must be the monorepo root (atArduino/) so both lib/ and
# packages/NoPorts_CYD/ are accessible:
#
#   docker build -f packages/NoPorts_CYD/Dockerfile -t noports-cyd-flasher .
#
# Or use docker-compose (recommended):
#   docker compose -f packages/NoPorts_CYD/docker-compose.yml up --build
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: build firmware
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# System dependencies needed by PlatformIO / esptool
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install PlatformIO and esptool into the system Python
RUN pip install --no-cache-dir platformio esptool

WORKDIR /build

# ---------------------------------------------------------------------------
# Layer cache optimisation:
#   Copy only what's needed to fetch registry packages first, so rebuilds
#   that change only source code skip the slow framework download.
# ---------------------------------------------------------------------------
COPY packages/NoPorts_CYD/platformio.ini   packages/NoPorts_CYD/platformio.ini
COPY packages/NoPorts_CYD/boards/          packages/NoPorts_CYD/boards/
COPY packages/NoPorts_CYD/partitions.csv   packages/NoPorts_CYD/partitions.csv

# Create a minimal stub so lib_extra_dirs path (../../lib) resolves during
# package scan, but no source code is included yet (keeps this layer cached).
RUN mkdir -p lib/NoPorts

WORKDIR /build/packages/NoPorts_CYD

# Fetch all registry packages + ESP32 toolchain (cached unless platformio.ini changes)
RUN platformio pkg install -e cyd2usb -e cyd2usb_s3

# ---------------------------------------------------------------------------
# Now copy the full source and build
# ---------------------------------------------------------------------------
WORKDIR /build

COPY lib/               lib/
COPY packages/NoPorts_CYD/  packages/NoPorts_CYD/

WORKDIR /build/packages/NoPorts_CYD

RUN platformio run -e cyd2usb -e cyd2usb_s3

# ---------------------------------------------------------------------------
# Merge each environment into a single self-contained binary.
#   ESP32  – bootloader at 0x1000
#   ESP32-S3 – bootloader at 0x0
# The merged binary can be written at offset 0x0 in one shot by ESPTool.js.
# ---------------------------------------------------------------------------
RUN BOOT=$(find /root/.platformio/packages -name "boot_app0.bin" | head -1) && \
    echo "Using boot_app0: $BOOT" && \
    \
    esptool.py --chip esp32 merge_bin \
        -o merged-cyd2usb.bin \
        0x1000  .pio/build/cyd2usb/bootloader.bin \
        0x8000  .pio/build/cyd2usb/partitions.bin \
        0xe000  "$BOOT" \
        0x10000 .pio/build/cyd2usb/firmware.bin && \
    \
    esptool.py --chip esp32s3 merge_bin \
        -o merged-cyd2usb_s3.bin \
        0x0     .pio/build/cyd2usb_s3/bootloader.bin \
        0x8000  .pio/build/cyd2usb_s3/partitions.bin \
        0xe000  "$BOOT" \
        0x10000 .pio/build/cyd2usb_s3/firmware.bin

# ---------------------------------------------------------------------------
# Build NVS-preserving "upgrade" split binaries using Python.
# Two writes per board skip the NVS region (0x9000–0xDFFF) entirely:
#   upgrade1 = bootloader + gap + partitions  (file starts at bootloader offset,
#              ends at ~0x82xx — well before NVS at 0x9000)
#   upgrade2 = boot_app0 + gap + firmware     (file starts at 0xe000)
# Each file is manually concatenated so it begins at exactly the flash address
# the manifest specifies — no merge_bin 0x0-padding issues.
# ---------------------------------------------------------------------------
RUN BOOT=$(find /root/.platformio/packages -name "boot_app0.bin" | head -1) && \
    python3 - "$BOOT" << 'PYEOF'
import sys, pathlib

BOOT  = sys.argv[1]
BUILD = pathlib.Path('.pio/build')

def pad(data, size):
    return data + b'\xff' * (size - len(data))

def write(name, data):
    pathlib.Path(name).write_bytes(data)
    print(f'{name}: {len(data)} bytes (0x{len(data):X})')

for chip, env, bl_off in [('esp32', 'cyd2usb', 0x1000), ('esp32s3', 'cyd2usb_s3', 0x0)]:
    d = BUILD / env
    bl = d.joinpath('bootloader.bin').read_bytes()
    pt = d.joinpath('partitions.bin').read_bytes()
    ba = pathlib.Path(BOOT).read_bytes()
    fw = d.joinpath('firmware.bin').read_bytes()

    # upgrade1: [bootloader padded to 0x8000 from bl_off] + partitions
    # written at flash offset bl_off  →  ends at bl_off + pad_size + len(pt)
    pad_size = 0x8000 - bl_off - len(bl)
    up1 = bl + b'\xff' * pad_size + pt
    write(f'upgrade1-{env}.bin', up1)

    # upgrade2: [boot_app0 padded to 0x2000] + firmware
    # written at flash offset 0xe000  →  starts well past NVS (0x9000)
    gap = 0x10000 - 0xe000 - len(ba)
    up2 = ba + b'\xff' * gap + fw
    write(f'upgrade2-{env}.bin', up2)
PYEOF

# ---------------------------------------------------------------------------
# Stage 2: minimal nginx web server
# ---------------------------------------------------------------------------
FROM nginx:alpine

# Remove default nginx config; replace with our own
RUN rm /etc/nginx/conf.d/default.conf
COPY packages/NoPorts_CYD/web/nginx.conf /etc/nginx/conf.d/noports.conf

# Web assets (static HTML + manifests)
COPY packages/NoPorts_CYD/web/ /usr/share/nginx/html/

# Merged firmware binaries (used by factory-reset manifests)
COPY --from=builder /build/packages/NoPorts_CYD/merged-cyd2usb.bin     /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_CYD/merged-cyd2usb_s3.bin  /usr/share/nginx/html/

# Split-merged upgrade binaries (used by NVS-preserving upgrade manifests)
COPY --from=builder /build/packages/NoPorts_CYD/upgrade1-cyd2usb.bin    /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_CYD/upgrade2-cyd2usb.bin    /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_CYD/upgrade1-cyd2usb_s3.bin /usr/share/nginx/html/
COPY --from=builder /build/packages/NoPorts_CYD/upgrade2-cyd2usb_s3.bin /usr/share/nginx/html/

EXPOSE 80

LABEL org.opencontainers.image.title="NoPorts CYD Flasher" \
      org.opencontainers.image.description="Browser-based firmware installer for NoPorts CYD / ESP32-S3 devices" \
      org.opencontainers.image.source="https://github.com/atsign-foundation/noports"
