# at_Arduino_NoPorts

**An experimental repository bringing the [atProtocol](https://atsign.com) and [NoPorts](https://noports.com) to ESP32 microcontrollers.**

> **Status: Experimental** — This project is under active development and
> should be considered experimental. It *is* working on real hardware, but
> APIs, structure, and functionality may change without notice.

---

## What Is This?

at_Arduino_NoPorts is a collection of Arduino/PlatformIO libraries and ready-to-flash
packages that let ESP32 devices participate in the atProtocol network. The
headline application is **NoPorts on ESP32** — an encrypted TCP relay daemon
(`sshnpd`) that lets you SSH into machines on your local network *through* an
ESP32, with **no open ports, no public IP, and no VPN**.

All tunnel traffic is **end-to-end encrypted** (AES-256-CTR) and
**RSA-2048 signed**.

---

## Supported Hardware

| Device | Chip | Connectivity | UI | Package |
|---|---|---|---|---|
| **CYD** (ESP32-2432S028R / v2) | ESP32 | WiFi | 2.8" touchscreen | `NoPorts_CYD` |
| **Freenove FNK0104** (CYD S3) | ESP32-S3 | WiFi | 2.8" touchscreen | `NoPorts_CYD` |
| **M5Stack Unit PoE-P4** | ESP32-P4 | Fast Ethernet (10/100) + PoE | Web UI | `NoPorts_PoE` |

### CYD — Cheap Yellow Display

The [ESP32-2432S028R](https://github.com/witnessmenow/ESP32-Cheap-Yellow-Display)
is an inexpensive (~$15) ESP32 board with a built-in 2.8" ILI9341 TFT
touchscreen. It provides a full onboard UI for WiFi setup, atSign enrollment,
and a live dashboard showing tunnel activity and system stats.

### M5Stack Unit PoE-P4

The [M5Stack Unit PoE-P4](https://docs.m5stack.com/en/unit/Unit_PoE-P4) is a
compact headless module powered by the ESP32-P4 (RISC-V, 360 MHz, 32 MB PSRAM).
It connects via **Fast Ethernet (10/100 Mbps)** using the onboard IP101GRI PHY,
and can be powered entirely over **PoE** (802.3af, up to 6 W) — no WiFi, no
USB power supply needed. Configuration and
monitoring are done through a built-in **web UI** accessible over the local
network. Designed for always-on, unattended deployment.

---

## Repository Structure

```
at_Arduino_NoPorts/
├── lib/                        # Reusable Arduino libraries
│   └── NoPorts/                # NoPorts daemon library (sshnpd for ESP32)
│
├── packages/                   # Ready-to-build PlatformIO projects
│   ├── NoPorts_CYD/            # NoPorts with touchscreen UI (CYD / ESP32-S3)
│   └── NoPorts_PoE/            # NoPorts headless daemon (M5Stack Unit PoE-P4)
│
└── web/                        # Browser-based firmware installer (docker compose)
```

> **Note:** The `at_client` Arduino library (atSDK for ESP32) lives in its own repository:
> [github.com/atsign-foundation/at_client_arduino](https://github.com/atsign-foundation/at_client_arduino)

### Libraries (`lib/`)

| Library | Description |
|---|---|
| **[NoPorts](lib/NoPorts/)** | NoPorts daemon (`sshnpd`) library — registers on the atProtocol network, accepts encrypted tunnel requests, and relays TCP traffic to local network services. |
| **[at_client](https://github.com/atsign-foundation/at_client_arduino)** *(external)* | Full ESP32 port of the [at_c SDK](https://github.com/atsign-foundation/at_c) — PKAM/CRAM auth, put/get/delete keys, monitor notifications, AES-256, RSA-2048, base64, and more. |

### Packages (`packages/`)

| Package | Target hardware | Description |
|---|---|---|
| **[NoPorts_CYD](packages/NoPorts_CYD/)** | ESP32-2432S028R, ESP32-S3 CYD variants | Touchscreen UI — WiFi setup, enrollment, live dashboard. |
| **[NoPorts_PoE](packages/NoPorts_PoE/)** | M5Stack Unit PoE-P4 (ESP32-P4) | Headless daemon with web UI. Connects over Gigabit Ethernet, powered by PoE. |

---

## Getting Started

### Prerequisites

- [PlatformIO](https://docs.platformio.org/en/latest/core/installation.html) (CLI or VS Code extension)
- Two **atSigns** — one for the ESP32 (device) and one for your laptop (manager). Get free atSigns at [atsign.com](https://atsign.com).

### CYD Quick Start

1. Clone the repo and open `packages/NoPorts_CYD` in PlatformIO.
2. Flash firmware — WiFi credentials and atSign enrollment are configured via the touchscreen on first boot.
3. Requires a **2.4 GHz WiFi** network (ESP32 does not support 5 GHz).

### M5Stack Unit PoE-P4 Quick Start

1. Clone the repo and open `packages/NoPorts_PoE` in PlatformIO (uses the [pioarduino](https://github.com/pioarduino/platform-espressif32) platform for ESP32-P4 support).
2. Flash firmware via USB-C.
3. Plug an Ethernet cable into the RJ45 port (PoE switch recommended — no USB power needed).
4. Navigate to the device's IP address in a browser to complete configuration.

### Browser-based Firmware Installer

A Docker-based web flasher lets you flash either device directly from a browser (Chrome/Edge) over WebSerial — no local toolchain needed:

```bash
docker compose up --build
# Then open http://localhost:8081
```

Or use the hosted installer at [cyd.crushware.com](https://cyd.crushware.com).

---

## Current Capabilities

| Feature | CYD | PoE-P4 |
|---|---|---|
| atProtocol authentication (PKAM) | ✓ | ✓ |
| Monitor for notifications | ✓ | ✓ |
| Ping / heartbeat responses | ✓ | ✓ |
| NPT (network port tunneling) | ✓ | ✓ |
| AES-CTR end-to-end encryption | ✓ | ✓ |
| RSA-2048 signing / verification | ✓ | ✓ |
| Multi-session relay (up to 4 concurrent) | ✓ | ✓ |
| APKAM enrollment | Touchscreen | Web UI |
| Live dashboard | Touchscreen | Web UI |
| Connectivity | WiFi | Fast Ethernet (10/100) |
| PoE power | — | ✓ |
| Hardware watchdog + heap recovery | ✓ | ✓ |
| Auto-recovery on network loss / DHCP expiry | ✓ | ✓ |

### Known Limitations

- **No SSH server on-device** — tunnels to TCP services on the local network
- **RSA operations are slow** — envelope verification takes 1–2 seconds
- **Limited concurrent tunnels** — realistically 2–4 simultaneous connections
- **NoPorts_PoE requires pioarduino** — the official espressif32 PlatformIO platform does not yet support ESP32-P4

---

## Contributing

**PRs and collaborators are VERY welcome!**

This has been a spare-time / weekend project, coded with the help of
**AI Architect** — primarily **Claude** and local LLMs running via
**[Ollama](https://ollama.com)**. There is plenty of room to help — whether
it's testing on new hardware, improving the UI, writing docs, fixing bugs, or
adding features. If you're interested in the atProtocol, embedded systems, or
encrypted networking on microcontrollers, jump in!

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR, and
note that this project follows our [Code of Conduct](code_of_conduct.md).

---

## License

This project is licensed under the [BSD 3-Clause License](LICENSE).

Copyright (c) 2022, The Atsign Foundation.

---

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md)
for responsible disclosure instructions.
