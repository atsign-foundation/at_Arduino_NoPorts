/**
 * @file noports_config.h
 * @brief Configuration structures and constants for the NoPorts daemon
 *
 * Mirrors sshnpd_params from the C sshnpd implementation, adapted for
 * Arduino/ESP32 constraints (no argparse, no filesystem paths by default).
 */

#ifndef NOPORTS_CONFIG_H
#define NOPORTS_CONFIG_H

#include <Arduino.h>

// ---------------------------------------------------------------------------
// Version & protocol constants (from sshnpd/version.h and sshnpd/sshnpd.h)
// ---------------------------------------------------------------------------
#define NOPORTS_VERSION          "1.5.0"
#define NOPORTS_CORE_PKG_VERSION "c1.5.0-arduino"

#define NOPORTS_DEFAULT_ROOT_HOST "root.atsign.org"
#define NOPORTS_DEFAULT_ROOT_PORT 64

#define NOPORTS_NS       "sshnp"   // atProtocol namespace (must match client)
#define NOPORTS_NS_LEN   5

// Monitor read timeout in milliseconds — keep short so the Arduino loop()
// remains responsive to touch input (the UI runs on the same core).
#define NOPORTS_MONITOR_READ_TIMEOUT_MS  100
// Noop timeout – after this many ms without data we send a noop/reconnect
#define NOPORTS_MONITOR_NOOP_TIMEOUT_MS  40000

// Maximum number of permitopen entries
#define NOPORTS_MAX_PERMITOPEN 255

// Maximum number of manager atSigns
#define NOPORTS_MAX_MANAGERS   16

// ---------------------------------------------------------------------------
// Notification key types (from sshnpd/sshnpd.h)
// ---------------------------------------------------------------------------
enum NoPortsNotificationKey {
  NK_NONE = 0,
  NK_SSHPUBLICKEY,          // not usable on Arduino
  NK_PING,
  NK_SSH_REQUEST,           // not usable on Arduino (no SSH server)
  NK_NPT_REQUEST,           // primary use-case on Arduino
  NK_GRACEFUL_SHUTDOWN,
};

// Must match the number of NK_* entries minus NK_NONE
#define NOPORTS_NOTIFICATION_KEYS_LEN 5

// ---------------------------------------------------------------------------
// PermitOpen entry
// ---------------------------------------------------------------------------
struct NoPortsPermitOpen {
  const char *host;  // e.g. "localhost"
  uint16_t    port;  // 0 means wildcard '*'
};

// ---------------------------------------------------------------------------
// NoPortsConfig – equivalent of sshnpd_params
// ---------------------------------------------------------------------------
struct NoPortsConfig {
  // Required
  const char *atsign;          // e.g. "@mydevice"
  const char *device_name;     // e.g. "esp32_sensor"
  const char *manager_list[NOPORTS_MAX_MANAGERS]; // allowed manager atSigns
  uint8_t     manager_count;

  // Optional
  const char *root_domain;     // NULL → NOPORTS_DEFAULT_ROOT_HOST
  uint16_t    root_port;       // 0   → NOPORTS_DEFAULT_ROOT_PORT

  uint16_t    local_sshd_port; // default 22 (used for ssh_request, not useful on Arduino)
  bool        verbose;
  bool        hide;            // if true, don't publish device info

  // PermitOpen – which host:port combinations the device is willing to relay
  NoPortsPermitOpen permitopen[NOPORTS_MAX_PERMITOPEN];
  uint8_t           permitopen_count;

  // Keys – raw base64-encoded atKeys (loaded from SPIFFS/LittleFS or hardcoded)
  // See noports_keys.h for helpers to load from filesystem
  const char *pkam_private_key_base64;
  const char *pkam_public_key_base64;
  const char *encrypt_private_key_base64;
  const char *encrypt_public_key_base64;
  const char *self_encryption_key_base64;
  const char *enrollment_id;              // APKAM enrollment ID (required for APKAM auth)

  // Callbacks (optional)
  // Called when a tunnel is established – host:port that is being relayed
  void (*on_tunnel_open)(const char *host, uint16_t port, const char *session_id);
  // Called when a tunnel closes
  void (*on_tunnel_close)(const char *session_id);
  // Called on ping
  void (*on_ping)(const char *from_atsign);
};

/**
 * @brief Apply sensible defaults to a NoPortsConfig
 */
inline void noports_config_init(NoPortsConfig *cfg) {
  memset(cfg, 0, sizeof(NoPortsConfig));
  cfg->root_domain     = NULL; // will use NOPORTS_DEFAULT_ROOT_HOST
  cfg->root_port       = 0;   // will use NOPORTS_DEFAULT_ROOT_PORT
  cfg->local_sshd_port = 22;
  cfg->verbose         = false;
  cfg->hide            = false;
  cfg->manager_count   = 0;
  cfg->permitopen_count = 0;
  cfg->on_tunnel_open  = NULL;
  cfg->on_tunnel_close = NULL;
  cfg->on_ping         = NULL;
}

#endif // NOPORTS_CONFIG_H
