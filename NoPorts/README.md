# NoPorts Arduino Library (sshnpd for ESP32)

An Arduino/ESP32 library implementing the NoPorts daemon (`sshnpd`), based on the
[C implementation](https://github.com/atsign-foundation/noports/tree/trunk/packages/c)
from the [Atsign Foundation's noports project](https://github.com/atsign-foundation/noports).

This allows an ESP32 to register on the atProtocol network and accept
**encrypted tunnel requests** from remote clients — without opening any
inbound ports, without a public IP address, and without traditional VPN
infrastructure.

---

## Is This Actually Possible?

**Short answer:** Yes, with caveats. Here's the honest breakdown.

### What Works

| Capability | Status | Notes |
|---|---|---|
| atProtocol authentication (PKAM) | **Feasible** | The `at_c` SDK already has an [Arduino generator](https://github.com/atsign-foundation/at_c/tree/trunk/generators/arduino/atsdk) targeting ESP32 |
| Monitor for notifications | **Feasible** | Long-lived TLS connection; ESP32 handles this well |
| Ping/heartbeat responses | **Feasible** | Simple JSON notify via atProtocol |
| NPT (network port tunneling) | **Feasible** | TCP relay via WiFiClient + FreeRTOS tasks |
| AES-CTR end-to-end encryption | **Feasible** | ESP32 has hardware AES acceleration via ESP-IDF mbedTLS |
| RSA-2048 signing/verification | **Feasible** | Supported by mbedTLS on ESP32, but slow (~1-2 seconds per operation) |
| Device info publishing | **Feasible** | Standard atProtocol notify |

### What Does NOT Work

| Capability | Status | Why |
|---|---|---|
| SSH request handling | **Not possible** | No SSH server on ESP32. Use NPT to tunnel to TCP services instead |
| SSH public key management | **Not applicable** | No `~/.ssh/authorized_keys` on Arduino |
| `fork()` for child processes | **Replaced** | Uses FreeRTOS tasks instead — this is the biggest architectural change |
| `pthreads` for relay | **Replaced** | Uses FreeRTOS tasks |
| POSIX signals | **Replaced** | Uses volatile bool flags |
| Filesystem paths | **Adapted** | Uses SPIFFS/LittleFS instead of POSIX filesystem |
| argparse CLI | **Removed** | Configuration via struct in code |
| Multiple concurrent tunnels | **Limited** | ESP32 has ~4 available sockets; max ~2-4 concurrent tunnels |

### Resource Considerations

| Resource | ESP32 Capacity | sshnpd Needs | Assessment |
|---|---|---|---|
| RAM | ~320KB usable | ~80-120KB for atclient + crypto | **Tight but workable** on ESP32 (not ESP8266) |
| Flash | 4MB typical | ~400KB for code + libs | **OK** |
| TLS connections | ~4-6 concurrent | 2 (monitor + worker) + 1 per tunnel | **2-4 tunnels max** |
| CPU (RSA-2048) | ~1-2s per operation | Signing + verification per request | **Acceptable** for low-frequency requests |

### Key Limitations

1. **ESP32 only** — ESP8266 lacks sufficient RAM and crypto capability
2. **No SSH** — only NPT (network port tunneling) to local TCP services
3. **Limited concurrent tunnels** — realistically 2-4 simultaneous connections
4. **RSA operations are slow** — envelope verification takes 1-2 seconds
5. **WiFi required** — no Ethernet without additional hardware
6. **atSDK maturity** — the atSDK (atclient, atchops, atlogger, cJSON) is bundled
   directly from the [at_c](https://github.com/atsign-foundation/at_c) trunk

---

## Prerequisites

### Hardware

- **ESP32** dev board (ESP32-WROOM, ESP32-S3, ESP32-C3, etc.)
- WiFi network
- USB cable for programming

### Software

1. **Arduino IDE 2.x** or **PlatformIO**
2. **ESP32 board support** — [install guide](https://docs.espressif.com/projects/arduino-esp32/en/latest/installing.html)
### atSign Setup

You need **two activated atSigns**:
- A **device atSign** (e.g., `@myesp32`) — used by the ESP32
- A **manager atSign** (e.g., `@mylaptop`) — used by the client connecting to the ESP32

Get free atSigns at [atsign.com](https://atsign.com) and activate them using
the [at_activate](https://github.com/atsign-foundation/at_c/tree/trunk/packages/atauth) tool.

---

## Installation

This library is **self-contained** — the atSDK (atclient, atchops, atlogger,
atcommons, cJSON) is bundled directly. No external `atsdk` dependency is needed.

### Step 1: Install the NoPorts Library

Copy the `NoPorts` folder to your Arduino libraries directory:

```bash
cp -r NoPorts ~/Documents/Arduino/libraries/
```

Or in PlatformIO, add it to your `lib` folder or reference it in `platformio.ini`:
```ini
[env:esp32]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps =
  NoPorts
```

### Step 2: Verify Installation

Open Arduino IDE, go to **Sketch > Include Library** — you should see
`NoPorts` in the list.

---

## Extracting Keys

The trickiest part is getting your atKeys into the right format. The `.atKeys`
file stores AES-encrypted keys — you need the **decrypted** base64 keys.

### Method 1: Load from SPIFFS (Recommended)

Upload your `.atKeys` file to the ESP32's SPIFFS partition and let the library
decrypt them automatically:

1. Rename your `@atsign_key.atKeys` file to `atkeys.json`
2. Place it in the `data/` folder of your sketch
3. Upload to SPIFFS:
   - Arduino IDE: Use the [ESP32 Sketch Data Upload](https://github.com/me-no-dev/arduino-esp32fs-plugin) plugin
   - PlatformIO: Run `pio run -t uploadfs`
4. Use the `LoadKeysFromSPIFFS` example

See [examples/LoadKeysFromSPIFFS/](examples/LoadKeysFromSPIFFS/).

### Method 2: Extract Keys Manually

Use this Python script to extract decrypted keys from your `.atKeys` file:

```python
#!/usr/bin/env python3
"""Extract decrypted atKeys for use in Arduino sketches."""
import json, base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_key(encrypted_b64, self_enc_key_bytes):
    data = base64.b64decode(encrypted_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(self_enc_key_bytes), modes.CBC(iv))
    dec = cipher.decryptor()
    plaintext = dec.update(ciphertext) + dec.finalize()
    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    return plaintext[:-pad_len].decode('utf-8')

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <path_to_atkeys_file>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    keys = json.load(f)

self_enc_key = base64.b64decode(keys['selfEncryptionKey'])

print("// Paste these into your Arduino sketch:")
print(f'const char *PKAM_PUBLIC_KEY  = "{decrypt_key(keys["aesPkamPublicKey"], self_enc_key)}";')
print(f'const char *PKAM_PRIVATE_KEY = "{decrypt_key(keys["aesPkamPrivateKey"], self_enc_key)}";')
print(f'const char *ENC_PUBLIC_KEY   = "{decrypt_key(keys["aesEncryptPublicKey"], self_enc_key)}";')
print(f'const char *ENC_PRIVATE_KEY  = "{decrypt_key(keys["aesEncryptPrivateKey"], self_enc_key)}";')
print(f'const char *SELF_ENC_KEY     = "{keys["selfEncryptionKey"]}";')
```

Run it:
```bash
pip install cryptography
python extract_keys.py ~/.atsign/keys/@myesp32_key.atKeys
```

**Security warning:** Hardcoding keys in your sketch means anyone with access to
the binary can extract them. SPIFFS is marginally better but still not secure.
For production use, consider secure elements (ATECC608A) or ESP32's flash
encryption.

---

## Quick Start

```cpp
#include <WiFi.h>
#include <NoPorts.h>

NoPortsDaemon daemon;

void setup() {
  Serial.begin(115200);

  WiFi.begin("MyWiFi", "MyPassword");
  while (WiFi.status() != WL_CONNECTED) delay(500);

  NoPortsConfig config;
  noports_config_init(&config);
  config.atsign      = "@myesp32";
  config.device_name = "esp32";
  config.manager_list[0] = "@mylaptop";
  config.manager_count   = 1;

  noports_keys_set(&config,
    "BASE64_PKAM_PUB...", "BASE64_PKAM_PRIV...",
    "BASE64_ENC_PUB...",  "BASE64_ENC_PRIV...",
    "BASE64_SELF_ENC...");

  config.permitopen[0] = { "localhost", 80 };
  config.permitopen_count = 1;

  daemon.begin(config);
}

void loop() {
  daemon.loop();
  delay(10);
}
```

Then from your laptop:
```bash
# Using the noports NPT client
npt -f @mylaptop -t @myesp32 -d esp32 \
    -rh localhost -rp 80 -lp 8080

# Your ESP32's port 80 is now available at localhost:8080
curl http://localhost:8080
```

---

## API Reference

### NoPortsConfig

```cpp
struct NoPortsConfig {
  const char *atsign;          // Device's atSign (required)
  const char *device_name;     // Device name for discovery (required)
  const char *manager_list[4]; // Allowed manager atSigns
  uint8_t     manager_count;   // Number of managers

  const char *root_domain;     // atDirectory host (default: root.atsign.org)
  uint16_t    root_port;       // atDirectory port (default: 64)
  bool        verbose;         // Enable debug logging
  bool        hide;            // Don't publish device info

  NoPortsPermitOpen permitopen[16]; // Allowed tunnel targets
  uint8_t           permitopen_count;

  // Key strings (base64-encoded, decrypted)
  const char *pkam_public_key_base64;
  const char *pkam_private_key_base64;
  const char *encrypt_public_key_base64;
  const char *encrypt_private_key_base64;
  const char *self_encryption_key_base64;

  // Callbacks (optional)
  void (*on_tunnel_open)(const char *host, uint16_t port, const char *session_id);
  void (*on_tunnel_close)(const char *session_id);
  void (*on_ping)(const char *from_atsign);
};
```

### NoPortsDaemon

| Method | Description |
|---|---|
| `bool begin(config)` | Initialize, authenticate, and start monitoring |
| `void loop()` | Process one notification (call from Arduino `loop()`) |
| `void stop()` | Gracefully shut down |
| `bool isRunning()` | Check if daemon is active |
| `NoPortsDaemonState getState()` | Get current state |
| `uint8_t getActiveRelayCount()` | Number of active tunnel relays |
| `const char* getLastError()` | Last error message |

### Key Loading

| Function | Description |
|---|---|
| `noports_keys_set(config, ...)` | Set keys from hardcoded base64 strings |
| `noports_keys_load_from_file(config, path)` | Load keys from SPIFFS/LittleFS JSON |
| `noports_keys_free(config)` | Free dynamically loaded keys |

---

## Architecture

### How It Maps to the C sshnpd

```
C sshnpd (Linux)                      Arduino NoPorts (ESP32)
─────────────────                      ──────────────────────
main.c (main function)           -->   NoPortsDaemon::begin()
daemon.c (main_loop)             -->   NoPortsDaemon::loop()
handle_ping.c                    -->   NoPortsDaemon::_handlePing()
handle_npt_request.c             -->   NoPortsDaemon::_handleNptRequest()
handle_ssh_request.c             -->   NOT IMPLEMENTED (no SSH on ESP32)
handle_sshpublickey.c            -->   NOT IMPLEMENTED
handler_commons.c                -->   NoPortsDaemon::_verifyEnvelope*()
run_srv_process.c + srv/srv.c    -->   noports_relay.cpp (FreeRTOS tasks)
params.c (argparse)              -->   NoPortsConfig struct
atkeys_file.c (filesystem)      -->   noports_keys.cpp (SPIFFS/LittleFS)
fork() + waitpid()               -->   xTaskCreatePinnedToCore()
pthreads                         -->   FreeRTOS tasks
POSIX signals                    -->   volatile bool flags
```

### Data Flow

```
                           atProtocol Cloud
                                │
                    ┌───────────┴───────────┐
                    │                       │
              Monitor Connection      Worker Connection
              (notifications)         (CRUD + notify)
                    │                       │
                    └───────────┬───────────┘
                                │
                         ┌──────┴──────┐
                         │  ESP32      │
                         │  NoPorts    │
                         │  Daemon     │
                         └──────┬──────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
              Ping Handler  NPT Handler  (other)
                    │           │
                    │     ┌─────┴─────┐
                    │     │   Relay   │  <-- FreeRTOS task
                    │     │  (srv)    │
                    │     └─────┬─────┘
                    │           │
                    │     ┌─────┴─────┐
                    │     │           │
                    │   RVD conn   Local conn
                    │   (WiFi)     (WiFi loopback)
                    │     │           │
                    │     │     Local TCP Service
                    │     │     (web server, etc.)
                    │     │
                    │   Rendezvous Server
                    │     │
                    │   Remote Client
```

---

## Troubleshooting

### "Failed to start daemon: Monitor PKAM auth failed"
- Check that your atSign is activated and the keys are correct
- Verify WiFi connectivity
- Check that `root.atsign.org:64` is reachable from your network
- Ensure the atKeys are properly decrypted (not still AES-encrypted)

### "No free relay slots"
- Maximum 4 concurrent tunnels — close existing connections first
- Check `getActiveRelayCount()` to see current usage

### Build errors about missing headers
- The atSDK is bundled in the library — no separate installation needed
- If you see MbedTLS errors, ensure you have the ESP32 board package installed
- Make sure your board is set to an ESP32 variant (not ESP8266)

### ESP32 runs out of memory / crashes
- Reduce `NOPORTS_MAX_RELAYS` to 2
- Reduce `RELAY_BUF_SIZE` in `noports_relay.cpp` from 4096 to 2048
- Use `ESP.getFreeHeap()` to monitor available RAM
- Avoid running other memory-intensive tasks alongside the daemon

### RSA operations are very slow
- RSA-2048 operations take 1-2 seconds on ESP32 — this is normal
- Each NPT request requires ~2-3 RSA operations (verify + sign)
- If this is a problem, consider fewer signature verifications (less secure)

---

## Security Considerations

1. **Key storage**: Hardcoded keys in flash are extractable. Use ESP32 flash
   encryption for production deployments.
2. **Network**: All atProtocol traffic is TLS-encrypted. Tunnel traffic is
   optionally AES-CTR encrypted end-to-end.
3. **Authentication**: Only manager atSigns in `manager_list` can request
   tunnels. Envelope signatures are verified with RSA-2048.
4. **PermitOpen**: Always configure `permitopen` to restrict which local
   services can be tunneled to.

---

## Dependencies

All atProtocol dependencies are **bundled** in this library:

| Component | Purpose | Source |
|---|---|---|
| atclient | atProtocol client, monitor, notify | Bundled from [at_c](https://github.com/atsign-foundation/at_c) |
| atchops | Crypto operations (AES, RSA, SHA, base64) | Bundled from [at_c](https://github.com/atsign-foundation/at_c) |
| atlogger | Logging (Serial.print-based on Arduino) | Bundled from [at_c](https://github.com/atsign-foundation/at_c) |
| atcommons | Common utilities, JSON provider | Bundled from [at_c](https://github.com/atsign-foundation/at_c) |
| cJSON | JSON parsing | Bundled from [at_c](https://github.com/atsign-foundation/at_c) |
| MbedTLS | TLS, AES, RSA, SHA | Built into ESP-IDF (no install needed) |
| WiFi | Network connectivity | Built into ESP32 Arduino core |

---

## Current Status: Alpha

This library is a **proof-of-concept** adaptation of the production C sshnpd.
It demonstrates that the core NoPorts daemon concept is viable on ESP32.

The atSDK source code is embedded directly from the
[at_c trunk](https://github.com/atsign-foundation/at_c) to eliminate the risk
of depending on a separately generated/maintained Arduino library.

**Known gaps:**
- WiFiClient loopback (`localhost` connections) on ESP32 may not work in all
  configurations — you may need to use the ESP32's own IP address
- No automated tests yet
- Multi-mode relay (control channel) is simplified compared to the full srv
- The embedded atSDK may need updates when the upstream at_c API changes

**Contributions welcome!** File issues at the
[noports repo](https://github.com/atsign-foundation/noports/issues).

---

## License

BSD-3-Clause — same as the upstream noports project.
