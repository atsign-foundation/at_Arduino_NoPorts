# at_Arduino_NoPorts

**An experimental monorepo bringing the [atProtocol](https://atsign.com) and [NoPorts](https://noports.com) to ESP32 microcontrollers.**

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

## Repository Structure

```
at_Arduino_NoPorts/
├── lib/                        # Reusable Arduino libraries
│   └── NoPorts/                # NoPorts daemon library (sshnpd for ESP32)
│
├── packages/                   # Ready-to-build PlatformIO projects
│   ├── NoPorts/                # Generic ESP32 NoPorts daemon
│   └── NoPorts_CYD/           # NoPorts with touchscreen UI for the CYD board
│
└── images/                     # Screenshots and reference images
```

> **Note:** The `at_client` Arduino library (atSDK for ESP32) now lives in its own repository:
> [github.com/atsign-foundation/at_client_arduino](https://github.com/atsign-foundation/at_client_arduino)

### Libraries (`lib/`)

| Library | Description |
|---|---|
| **[NoPorts](lib/NoPorts/)** | NoPorts daemon (`sshnpd`) library — registers on the atProtocol network, accepts encrypted tunnel requests, and relays TCP traffic to local network services. |
| **[at_client](https://github.com/atsign-foundation/at_client_arduino)** *(external)* | Full ESP32 port of the [at_c SDK](https://github.com/atsign-foundation/at_c) — PKAM/CRAM auth, put/get/delete keys, monitor notifications, AES-256, RSA-2048, base64, and more. Required dependency of NoPorts, now in its own repo. |

### Packages (`packages/`)

| Package | Description |
|---|---|
| **[NoPorts](packages/NoPorts/)** | A PlatformIO project targeting generic ESP32 boards (ESP32-WROOM-32, ESP32-S3, ESP32-C3, etc.). Configuration is done in `main.cpp`. |
| **[NoPorts_CYD](packages/NoPorts_CYD/)** | A PlatformIO project for the **CYD (Cheap Yellow Display)** ESP32-2432S028R board. Includes a touchscreen UI for WiFi setup, device enrollment, and a live dashboard showing tunnel activity, throughput, and system stats. |

---

## Hardware

This project is actively developed and tested on:

- **ESP32-2432S028R** (CYD — "Cheap Yellow Display") — standard micro-USB version
- **ESP32-2432S028Rv2** (CYD2USB) — newer version with micro-USB + USB-C

It should also work on **other ESP32 boards** (ESP32-WROOM-32, ESP32-S3,
ESP32-C3, etc.) using the generic `packages/NoPorts` project — but your
mileage may vary. If you try it on other hardware, please open an issue or PR
to let us know how it went!

---

## Getting Started

### Prerequisites

- [PlatformIO](https://docs.platformio.org/en/latest/core/installation.html) (CLI or VS Code extension)
- Two **atSigns** — one for the ESP32 (device) and one for your laptop (manager). Get free atSigns at [atsign.com](https://atsign.com).
- A 2.4 GHz WiFi network (ESP32 does not support 5 GHz)

### Quick Start

1. Clone the repo:
   ```bash
   git clone https://github.com/atsign-foundation/at_Arduino_NoPorts.git
   cd at_Arduino_NoPorts
   ```

2. Pick a package:
   - **CYD board?** → `cd packages/NoPorts_CYD` — WiFi and enrollment are configured via the touchscreen.
   - **Generic ESP32?** → `cd packages/NoPorts` — edit `src/main.cpp` with your WiFi credentials, atSigns, and `permitopen` entries.

3. Place your `.atKeys` file (renamed to `atkeys.json`) in the `data/` directory.

4. Build and flash:
   ```bash
   pio run -t uploadfs   # Upload atkeys.json to the filesystem
   pio run -t upload     # Flash the firmware
   pio device monitor -b 115200
   ```

For detailed setup instructions, see the README in each package directory.

---

## Current Capabilities

| Feature | Status |
|---|---|
| atProtocol authentication (PKAM) | Working |
| Monitor for notifications | Working |
| Ping / heartbeat responses | Working |
| NPT (network port tunneling) | Working |
| AES-CTR end-to-end encryption | Working |
| RSA-2048 signing / verification | Working |
| Multi-session relay (up to 4 concurrent) | Working |
| APKAM enrollment (onboard & enroll) | Working |
| Touchscreen UI (CYD) | Working |

### Known Limitations

- **ESP32 only** — ESP8266 lacks sufficient RAM and crypto support
- **No SSH server on the ESP32** — it tunnels to TCP services on the local network
- **RSA operations are slow** — envelope verification takes 1–2 seconds on ESP32
- **Limited concurrent tunnels** — realistically 2–4 simultaneous connections

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
