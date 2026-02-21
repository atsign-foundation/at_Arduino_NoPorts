/**
 * @file noports_daemon.cpp
 * @brief Main NoPorts daemon implementation for ESP32
 *
 * This is the Arduino/ESP32 adaptation of:
 *   - packages/c/sshnpd/src/main.c     (initialization flow)
 *   - packages/c/sshnpd/src/daemon.c   (main_loop / notification dispatch)
 *   - packages/c/sshnpd/src/handle_ping.c
 *   - packages/c/sshnpd/src/handle_npt_request.c
 *   - packages/c/sshnpd/src/handler_commons.c
 *
 * Key adaptations from the C sshnpd:
 *   - No fork(): relay processes use FreeRTOS tasks (see noports_relay.cpp)
 *   - No pthreads: FreeRTOS tasks
 *   - No POSIX signals: volatile bool flag
 *   - No filesystem for authorized_keys: not applicable to Arduino
 *   - No SSH support: only NPT (network port tunneling)
 *   - No argparse: configuration via NoPortsConfig struct
 *   - No environment variables: all config is explicit
 */

#include "noports/noports_daemon.h"
#include "noports/noports_log.h"
#include <stdarg.h>

// === Embedded atSDK includes ===
// These are bundled directly in this library (no external atsdk dependency)
extern "C" {
  #include "atclient/atclient.h"
  #include "atclient/atclient_utils.h"
  #include "atclient/atkey.h"
  #include "atclient/atkeys.h"
  #include "atclient/monitor.h"
  #include "atclient/notify.h"
  #include "atclient/string_utils.h"
  #include "atclient/json.h"
  #include "atchops/aes.h"
  #include "atchops/iv.h"
  #include "atchops/rsa.h"
  #include "atchops/rsa_key.h"
  #include "atchops/sha.h"
  #include "atchops/base64.h"
  #include "atlogger/atlogger.h"
}

#define TAG "noports"

// Notification key string mapping (from daemon.c)
static const struct {
  const char *str;
  NoPortsNotificationKey key;
} _notification_key_map[] = {
  { "",                  NK_NONE },
  { "sshpublickey",      NK_SSHPUBLICKEY },
  { "ping",              NK_PING },
  { "ssh_request",       NK_SSH_REQUEST },
  { "npt_request",       NK_NPT_REQUEST },
  { "graceful_shutdown", NK_GRACEFUL_SHUTDOWN },
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

NoPortsDaemon::NoPortsDaemon()
  : _state(DAEMON_UNINITIALIZED)
  , _should_run(false)
  , _monitor_ctx(nullptr)
  , _worker_ctx(nullptr)
  , _atkeys(nullptr)
  , _signing_key(nullptr)
  , _monitor_options(nullptr)
  , _worker_options(nullptr)
  , _ping_response(nullptr)
  , _monitor_regex(nullptr)
  , _root_port(0)
  , _relay_count(0)
  , _timeout_counter(0)
  , _reconnect_failures(0) {
  memset(_last_error, 0, sizeof(_last_error));
  memset(_root_host, 0, sizeof(_root_host));
  // Don't memset _relays — it contains WiFiClient C++ objects whose
  // constructors have already run.  Zero only the POD fields.
  for (int i = 0; i < NOPORTS_MAX_RELAYS; i++) {
    memset(&_relays[i].config, 0, sizeof(NoPortsRelayConfig));
    _relays[i].state = RELAY_IDLE;
    _relays[i].task_handle = NULL;
    _relays[i].should_run = false;
    _relays[i].bytes_in = 0;
    _relays[i].bytes_out = 0;
    _relays[i].start_ms = 0;
    _relays[i].encrypter = NULL;
    _relays[i].decrypter = NULL;
  }
}

NoPortsDaemon::~NoPortsDaemon() {
  stop();

  // Free allocated atSDK objects
  if (_monitor_ctx) {
    atclient_monitor_free((atclient *)_monitor_ctx);
    free(_monitor_ctx);
  }
  if (_worker_ctx) {
    atclient_free((atclient *)_worker_ctx);
    free(_worker_ctx);
  }
  if (_atkeys) {
    atclient_atkeys_free((atclient_atkeys *)_atkeys);
    free(_atkeys);
  }
  if (_signing_key) {
    atchops_rsa_key_private_key_free((atchops_rsa_key_private_key *)_signing_key);
    free(_signing_key);
  }
  if (_monitor_options) {
    atclient_authenticate_options_free((atclient_authenticate_options *)_monitor_options);
    free(_monitor_options);
  }
  if (_worker_options) {
    atclient_authenticate_options_free((atclient_authenticate_options *)_worker_options);
    free(_worker_options);
  }
  if (_ping_response) {
    free(_ping_response);
  }
  if (_monitor_regex) {
    free(_monitor_regex);
  }
}

// ============================================================================
// Public API
// ============================================================================

bool NoPortsDaemon::begin(const NoPortsConfig &config) {
  _state = DAEMON_INITIALIZING;
  memcpy(&_config, &config, sizeof(NoPortsConfig));

  // ---- Validate config ----
  if (!_config.atsign || strlen(_config.atsign) == 0) {
    _setError("atSign is required");
    _state = DAEMON_ERROR;
    return false;
  }
  if (!_config.device_name || strlen(_config.device_name) == 0) {
    _setError("device_name is required");
    _state = DAEMON_ERROR;
    return false;
  }
  if (_config.manager_count == 0) {
    _setError("At least one manager atSign is required");
    _state = DAEMON_ERROR;
    return false;
  }
  if (!_config.pkam_private_key_base64 ||
      !_config.encrypt_private_key_base64 ||
      !_config.encrypt_public_key_base64) {
    _setError("atKeys (PKAM and encryption keys) are required");
    _state = DAEMON_ERROR;
    return false;
  }

  // ---- Setup logging ----
  if (_config.verbose) {
    NOPORTS_LOGI(TAG, "Verbose mode enabled");
  }

  // ---- Setup root host/port ----
  if (_config.root_domain) {
    // Parse domain:port if colon present
    const char *colon = strchr(_config.root_domain, ':');
    if (colon) {
      size_t host_len = colon - _config.root_domain;
      if (host_len >= sizeof(_root_host)) {
        _setError("Root domain host too long");
        _state = DAEMON_ERROR;
        return false;
      }
      snprintf(_root_host, sizeof(_root_host), "%.*s", (int)host_len, _config.root_domain);
      _root_port = (uint16_t)atoi(colon + 1);
    } else {
      snprintf(_root_host, sizeof(_root_host), "%s", _config.root_domain);
      _root_port = NOPORTS_DEFAULT_ROOT_PORT;
    }
  } else {
    snprintf(_root_host, sizeof(_root_host), "%s", NOPORTS_DEFAULT_ROOT_HOST);
    _root_port = NOPORTS_DEFAULT_ROOT_PORT;
  }

  if (_config.root_port != 0) {
    _root_port = _config.root_port;
  }

  NOPORTS_LOGI(TAG, "Root server: %s:%d", _root_host, _root_port);

  // ---- Load atKeys ----
  _atkeys = calloc(1, sizeof(atclient_atkeys));
  if (!_atkeys) {
    _setError("Failed to allocate atkeys");
    _state = DAEMON_ERROR;
    return false;
  }
  atclient_atkeys_init((atclient_atkeys *)_atkeys);

  atclient_atkeys *keys = (atclient_atkeys *)_atkeys;

  // Populate keys from the base64 strings
  int res = 0;

  if (_config.pkam_public_key_base64) {
    res = atchops_rsa_key_populate_public_key(&keys->pkam_public_key,
                                              _config.pkam_public_key_base64,
                                              strlen(_config.pkam_public_key_base64));
    if (res != 0) {
      _setError("Failed to populate PKAM public key: %d", res);
      _state = DAEMON_ERROR;
      return false;
    }
  }

  res = atchops_rsa_key_populate_private_key(&keys->pkam_private_key,
                                             _config.pkam_private_key_base64,
                                             strlen(_config.pkam_private_key_base64));
  if (res != 0) {
    _setError("Failed to populate PKAM private key: %d", res);
    _state = DAEMON_ERROR;
    return false;
  }

  if (_config.encrypt_public_key_base64) {
    res = atchops_rsa_key_populate_public_key(&keys->encrypt_public_key,
                                              _config.encrypt_public_key_base64,
                                              strlen(_config.encrypt_public_key_base64));
    if (res != 0) {
      _setError("Failed to populate encrypt public key: %d", res);
      _state = DAEMON_ERROR;
      return false;
    }
  }

  res = atchops_rsa_key_populate_private_key(&keys->encrypt_private_key,
                                             _config.encrypt_private_key_base64,
                                             strlen(_config.encrypt_private_key_base64));
  if (res != 0) {
    _setError("Failed to populate encrypt private key: %d", res);
    _state = DAEMON_ERROR;
    return false;
  }

  if (_config.self_encryption_key_base64) {
    res = atclient_atkeys_set_self_encryption_key_base64(keys,
                                  _config.self_encryption_key_base64,
                                  strlen(_config.self_encryption_key_base64));
    if (res != 0) {
      NOPORTS_LOGW(TAG, "Failed to set self encryption key: %d (non-fatal)", res);
    }
  }

  // Set enrollment ID (required for APKAM-enrolled keys)
  if (_config.enrollment_id) {
    res = atclient_atkeys_set_enrollment_id(keys,
                                  _config.enrollment_id,
                                  strlen(_config.enrollment_id));
    if (res != 0) {
      NOPORTS_LOGW(TAG, "Failed to set enrollment_id: %d (non-fatal)", res);
    } else {
      NOPORTS_LOGI(TAG, "Enrollment ID set: %s", _config.enrollment_id);
    }
  }

  // ---- Create signing key copy (from encrypt private key, same as C sshnpd) ----
  _signing_key = calloc(1, sizeof(atchops_rsa_key_private_key));
  if (!_signing_key) {
    _setError("Failed to allocate signing key");
    _state = DAEMON_ERROR;
    return false;
  }
  atchops_rsa_key_private_key_init((atchops_rsa_key_private_key *)_signing_key);
  res = atchops_rsa_key_private_key_clone(&keys->encrypt_private_key,
                                          (atchops_rsa_key_private_key *)_signing_key);
  if (res != 0) {
    _setError("Failed to clone signing key: %d", res);
    _state = DAEMON_ERROR;
    return false;
  }

  // ---- Authenticate ----
  _state = DAEMON_AUTHENTICATING;
  if (!_authenticate()) {
    _state = DAEMON_ERROR;
    return false;
  }

  // ---- Build ping response ----
  _buildPingResponse();

  // ---- Publish device info ----
  if (!_config.hide) {
    _publishDeviceInfo();
  }

  // ---- Start monitor ----
  if (!_startMonitor()) {
    _state = DAEMON_ERROR;
    return false;
  }

  _should_run = true;
  _state = DAEMON_MONITORING;
  NOPORTS_LOGI(TAG, "NoPorts daemon started for %s (device: %s)",
               _config.atsign, _config.device_name);

  return true;
}

void NoPortsDaemon::loop() {
  if (_state != DAEMON_MONITORING || !_should_run) return;

  // Clean up finished relays
  _cleanupFinishedRelays();

  // Read next monitor message
  atclient_monitor_message message;
  atclient_monitor_message_init(&message);

  atclient *monitor = (atclient *)_monitor_ctx;
  atclient *worker  = (atclient *)_worker_ctx;

  // Check if we need to reconnect
  if (_timeout_counter * NOPORTS_MONITOR_READ_TIMEOUT_MS > NOPORTS_MONITOR_NOOP_TIMEOUT_MS) {
    if (!_reconnectMonitor()) {
      _timeout_counter = NOPORTS_MONITOR_NOOP_TIMEOUT_MS / NOPORTS_MONITOR_READ_TIMEOUT_MS + 1;
      atclient_monitor_message_free(&message);
      return;
    }
    _timeout_counter = 0;
  }

  int ret = atclient_monitor_read(monitor, worker, &message, NULL);
  if (ret != 0) {
    // The monitor uses the worker to fetch shared encryption keys for
    // decrypting notifications. If the worker's TLS connection dropped
    // (common while a relay is active), decrypt fails and we get ret=-1.
    // Try reconnecting the worker first — it's cheaper than a full
    // monitor reconnect and usually fixes the issue.
    NOPORTS_LOGW(TAG, "Monitor read failed (ret: %d), reconnecting worker first", ret);
    if (_reconnectWorker()) {
      NOPORTS_LOGI(TAG, "Worker reconnected, will retry monitor read");
      // Don't bump timeout — let the next loop() iteration retry with
      // the fresh worker connection.
    } else {
      NOPORTS_LOGW(TAG, "Worker reconnect also failed, will reconnect monitor");
      _timeout_counter = NOPORTS_MONITOR_NOOP_TIMEOUT_MS / NOPORTS_MONITOR_READ_TIMEOUT_MS + 1;
    }
    atclient_monitor_message_free(&message);
    return;
  }

  switch (message.type) {
    case ATCLIENT_MONITOR_MESSAGE_TYPE_EMPTY:
      _timeout_counter++;
      break;

    case ATCLIENT_MONITOR_ERROR_READ:
      _timeout_counter = NOPORTS_MONITOR_NOOP_TIMEOUT_MS / NOPORTS_MONITOR_READ_TIMEOUT_MS + 1;
      break;

    case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION: {
      _timeout_counter = 0;
      _handleNotification(&message);
      break;
    }

    case ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE:
      _timeout_counter = 0;
      NOPORTS_LOGD(TAG, "Data response: %s", message.data_response);
      break;

    case ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE:
      _timeout_counter = 0;
      NOPORTS_LOGE(TAG, "Error response: %s", message.error_response);
      break;

    case ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION:
      _timeout_counter = NOPORTS_MONITOR_NOOP_TIMEOUT_MS / NOPORTS_MONITOR_READ_TIMEOUT_MS + 1;
      NOPORTS_LOGE(TAG, "Failed to parse notification");
      break;

    case ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION:
      NOPORTS_LOGE(TAG, "Failed to decrypt notification, reconnecting worker");
      _reconnectWorker();
      // Don't force monitor reconnect — the monitor stream is fine,
      // only the worker (used for key lookup) was stale.
      break;

    default:
      break;
  }

  atclient_monitor_message_free(&message);
}

void NoPortsDaemon::stop() {
  _should_run = false;

  // Stop all active relays
  for (int i = 0; i < NOPORTS_MAX_RELAYS; i++) {
    if (noports_relay_is_running(&_relays[i])) {
      noports_relay_stop(&_relays[i]);
    }
  }

  _state = DAEMON_STOPPED;
  NOPORTS_LOGI(TAG, "NoPorts daemon stopped");
}

bool NoPortsDaemon::isRunning() const {
  return _state == DAEMON_MONITORING && _should_run;
}

NoPortsDaemonState NoPortsDaemon::getState() const {
  return _state;
}

uint8_t NoPortsDaemon::getActiveRelayCount() const {
  uint8_t count = 0;
  for (int i = 0; i < NOPORTS_MAX_RELAYS; i++) {
    if (noports_relay_is_running(&_relays[i])) {
      count++;
    }
  }
  return count;
}

const char* NoPortsDaemon::getLastError() const {
  return _last_error;
}

void NoPortsDaemon::getThroughput(uint32_t &bytes_in, uint32_t &bytes_out) const {
  bytes_in = 0;
  bytes_out = 0;
  for (int i = 0; i < NOPORTS_MAX_RELAYS; i++) {
    bytes_in  += _relays[i].bytes_in;
    bytes_out += _relays[i].bytes_out;
  }
}

// ============================================================================
// Private: Authentication
// ============================================================================

bool NoPortsDaemon::_authenticate() {
  atclient_atkeys *keys = (atclient_atkeys *)_atkeys;
  int res;

  // ---- Monitor client ----
  _monitor_ctx = calloc(1, sizeof(atclient));
  if (!_monitor_ctx) {
    _setError("Failed to allocate monitor client");
    return false;
  }
  atclient_monitor_init((atclient *)_monitor_ctx);

  _monitor_options = calloc(1, sizeof(atclient_authenticate_options));
  if (!_monitor_options) {
    _setError("Failed to allocate monitor options");
    return false;
  }
  atclient_authenticate_options_init((atclient_authenticate_options *)_monitor_options);
  atclient_authenticate_options_set_atdirectory_host(
    (atclient_authenticate_options *)_monitor_options, _root_host);
  atclient_authenticate_options_set_atdirectory_port(
    (atclient_authenticate_options *)_monitor_options, _root_port);

  atclient_monitor_set_read_timeout((atclient *)_monitor_ctx, NOPORTS_MONITOR_READ_TIMEOUT_MS);

  NOPORTS_LOGI(TAG, "Authenticating monitor client for %s...", _config.atsign);
  res = atclient_monitor_pkam_authenticate(
    (atclient *)_monitor_ctx, _config.atsign, keys,
    (atclient_authenticate_options *)_monitor_options);

  if (res != 0) {
    _setError("Monitor PKAM auth failed: %d", res);
    return false;
  }
  NOPORTS_LOGI(TAG, "Monitor client authenticated");

  // ---- Worker client ----
  _worker_ctx = calloc(1, sizeof(atclient));
  if (!_worker_ctx) {
    _setError("Failed to allocate worker client");
    return false;
  }
  atclient_init((atclient *)_worker_ctx);

  _worker_options = calloc(1, sizeof(atclient_authenticate_options));
  if (!_worker_options) {
    _setError("Failed to allocate worker options");
    return false;
  }
  atclient_authenticate_options_init((atclient_authenticate_options *)_worker_options);
  atclient_authenticate_options_set_atdirectory_host(
    (atclient_authenticate_options *)_worker_options, _root_host);
  atclient_authenticate_options_set_atdirectory_port(
    (atclient_authenticate_options *)_worker_options, _root_port);

  NOPORTS_LOGI(TAG, "Authenticating worker client for %s...", _config.atsign);
  res = atclient_pkam_authenticate(
    (atclient *)_worker_ctx, _config.atsign, keys,
    (atclient_authenticate_options *)_worker_options, NULL);

  if (res != 0) {
    _setError("Worker PKAM auth failed: %d", res);
    return false;
  }
  NOPORTS_LOGI(TAG, "Worker client authenticated");

  return true;
}

// ============================================================================
// Private: Monitor setup
// ============================================================================

bool NoPortsDaemon::_startMonitor() {
  // Build regex: "device.sshnp@"
  size_t regexlen = strlen(_config.device_name) + strlen(NOPORTS_NS) + 3;
  _monitor_regex = (char *)malloc(regexlen);
  if (!_monitor_regex) {
    _setError("Failed to allocate monitor regex");
    return false;
  }
  snprintf(_monitor_regex, regexlen, "%s.%s@", _config.device_name, NOPORTS_NS);

  NOPORTS_LOGI(TAG, "Starting monitor with regex: %s", _monitor_regex);

  int res = atclient_monitor_start((atclient *)_monitor_ctx, _monitor_regex);
  if (res != 0) {
    _setError("Failed to start monitor: %d", res);
    return false;
  }

  NOPORTS_LOGI(TAG, "Monitor started successfully");
  return true;
}

// ============================================================================
// Private: Device info / Ping response
// ============================================================================

void NoPortsDaemon::_buildPingResponse() {
  cJSON *ping_json = cJSON_CreateObject();
  cJSON_AddStringToObject(ping_json, "devicename", _config.device_name);
  cJSON_AddStringToObject(ping_json, "version", NOPORTS_VERSION);
  cJSON_AddStringToObject(ping_json, "corePackageVersion", NOPORTS_CORE_PKG_VERSION);

  cJSON *features = cJSON_CreateObject();
  cJSON_AddBoolToObject(features, "srAuth", true);
  cJSON_AddBoolToObject(features, "srE2ee", true);
  cJSON_AddBoolToObject(features, "acceptsPublicKeys", false); // no SSH keys on Arduino
  cJSON_AddBoolToObject(features, "supportsPortChoice", true);
  cJSON_AddBoolToObject(features, "adjustableTimeout", true);
  cJSON_AddBoolToObject(features, "controlChannelHeartbeats", true);
  cJSON_AddBoolToObject(features, "twinKeys", true);
  cJSON_AddItemToObject(ping_json, "supportedFeatures", features);

  // Allowed services from permitopen config
  cJSON *allowed = cJSON_CreateArray();
  for (uint8_t i = 0; i < _config.permitopen_count; i++) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s:%u",
             _config.permitopen[i].host,
             (unsigned int)_config.permitopen[i].port);
    cJSON_AddItemToArray(allowed, cJSON_CreateString(buf));
  }
  cJSON_AddItemToObject(ping_json, "allowedServices", allowed);

  _ping_response = cJSON_PrintUnformatted(ping_json);
  cJSON_Delete(ping_json);

  NOPORTS_LOGD(TAG, "Ping response: %s", _ping_response ? _ping_response : "NULL");
}

bool NoPortsDaemon::_publishDeviceInfo() {
  // Publish username info key for each manager
  // This mirrors handle_username_keys from the C sshnpd
  atclient *worker = (atclient *)_worker_ctx;

  for (uint8_t i = 0; i < _config.manager_count; i++) {
    // Build the key: "username.device_name.sshnp"
    atclient_atkey info_key;
    atclient_atkey_init(&info_key);

    size_t keynamelen = strlen("username") + strlen(_config.device_name) + 2;
    char keyname[keynamelen];
    snprintf(keyname, keynamelen, "username.%s", _config.device_name);

    int res = atclient_atkey_create_shared_key(&info_key, keyname,
                                               _config.atsign,
                                               _config.manager_list[i],
                                               NOPORTS_NS);
    if (res != 0) {
      NOPORTS_LOGW(TAG, "Failed to create device info key for %s", _config.manager_list[i]);
      atclient_atkey_free(&info_key);
      continue;
    }

    atclient_atkey_metadata *metadata = &info_key.metadata;
    atclient_atkey_metadata_set_is_public(metadata, false);
    atclient_atkey_metadata_set_is_encrypted(metadata, true);

    atclient_notify_params notify_params;
    atclient_notify_params_init(&notify_params);
    atclient_notify_params_set_atkey(&notify_params, &info_key);
    atclient_notify_params_set_value(&notify_params, "esp32");
    atclient_notify_params_set_operation(&notify_params, ATCLIENT_NOTIFY_OPERATION_UPDATE);

    res = _notifyWithRetry(worker, &notify_params, NULL);
    if (res != 0) {
      NOPORTS_LOGW(TAG, "Failed to publish device info to %s: %d", _config.manager_list[i], res);
    } else {
      NOPORTS_LOGI(TAG, "Published device info to %s", _config.manager_list[i]);
    }

    atclient_notify_params_free(&notify_params);
    atclient_atkey_free(&info_key);
  }

  return true;
}

// ============================================================================
// Private: Notification handling (from daemon.c)
// ============================================================================

void NoPortsDaemon::_handleNotification(void *msg) {
  atclient_monitor_message *message = (atclient_monitor_message *)msg;

  bool is_init = atclient_atnotification_is_decrypted_value_initialized(message->notification);
  bool has_key = atclient_atnotification_is_key_initialized(message->notification);

  NOPORTS_LOGI(TAG, "Notification received: key_init=%d val_init=%d id=%s",
               has_key, is_init,
               message->notification->id ? message->notification->id : "null");
  if (has_key) {
    NOPORTS_LOGI(TAG, "  key=%s from=%s to=%s",
                 message->notification->key ? message->notification->key : "null",
                 message->notification->from ? message->notification->from : "null",
                 message->notification->to ? message->notification->to : "null");
  }

  if (!is_init) {
    NOPORTS_LOGI(TAG, "Skipping notification (no decrypted value)");
    return;
  }

  if (!has_key || strcmp(message->notification->id, "-1") == 0) {
    NOPORTS_LOGI(TAG, "Skipping notification (no key or id=-1)");
    return;
  }

  char *key = message->notification->key;

  // Strip "$device.$namespace$from" from the back
  size_t tail_len = strlen(_config.device_name) + strlen(NOPORTS_NS) +
                    strlen(message->notification->from) + 3;
  char *tail = (char *)malloc(tail_len);
  if (!tail) return;

  sprintf(tail, ".%s.%s%s", _config.device_name, NOPORTS_NS, message->notification->from);
  char *tailstart = strstr(key, tail);
  free(tail);

  if (tailstart == NULL) {
    NOPORTS_LOGI(TAG, "Skipping: couldn't find tail in key");
    return;
  }
  *tailstart = '\0'; // reterminate

  // Strip notification.to from the front
  char *head = message->notification->to;
  size_t head_len = strlen(head);

  if (strlen(key) < head_len) {
    NOPORTS_LOGI(TAG, "Skipping: key too short for head strip");
    return;
  }

  if (strncmp(key, head, head_len) != 0) {
    NOPORTS_LOGI(TAG, "Skipping: head mismatch");
    return;
  }

  key += head_len + 1; // +1 for ":"

  NOPORTS_LOGI(TAG, "Parsed notification key: '%s'", key);

  // Identify notification type
  NoPortsNotificationKey nk = NK_NONE;
  for (int i = 1; i < NOPORTS_NOTIFICATION_KEYS_LEN; i++) {
    if (strcmp(key, _notification_key_map[i].str) == 0) {
      nk = _notification_key_map[i].key;
      break;
    }
  }

  // Dispatch
  switch (nk) {
    case NK_PING:
      NOPORTS_LOGI(TAG, "Handling ping from %s", message->notification->from);
      _handlePing(message);
      break;

    case NK_NPT_REQUEST:
      NOPORTS_LOGI(TAG, "Handling NPT request from %s", message->notification->from);
      _handleNptRequest(message);
      break;

    case NK_SSH_REQUEST:
      NOPORTS_LOGW(TAG, "SSH request not supported on Arduino/ESP32");
      break;

    case NK_SSHPUBLICKEY:
      NOPORTS_LOGW(TAG, "SSH public key not supported on Arduino/ESP32");
      break;

    case NK_GRACEFUL_SHUTDOWN:
      NOPORTS_LOGI(TAG, "Graceful shutdown requested");
      _handleGracefulShutdown();
      break;

    case NK_NONE:
    default:
      NOPORTS_LOGD(TAG, "Unknown notification key: %s", key);
      break;
  }
}

// ============================================================================
// Private: Ping handler (from handle_ping.c)
// ============================================================================

void NoPortsDaemon::_handlePing(void *msg) {
  atclient_monitor_message *message = (atclient_monitor_message *)msg;
  atclient *worker = (atclient *)_worker_ctx;

  if (!_ping_response) {
    NOPORTS_LOGE(TAG, "Ping response not built");
    return;
  }

  atclient_atkey pingkey;
  atclient_atkey_init(&pingkey);

  size_t keynamelen = strlen("heartbeat") + strlen(_config.device_name) + 2;
  char keyname[keynamelen];
  snprintf(keyname, keynamelen, "heartbeat.%s", _config.device_name);

  int res = atclient_atkey_create_shared_key(&pingkey, keyname,
                                             _config.atsign,
                                             message->notification->from,
                                             NOPORTS_NS);
  if (res != 0) {
    NOPORTS_LOGE(TAG, "Failed to create ping key");
    atclient_atkey_free(&pingkey);
    return;
  }

  atclient_atkey_metadata *metadata = &pingkey.metadata;
  atclient_atkey_metadata_set_is_public(metadata, false);
  atclient_atkey_metadata_set_is_encrypted(metadata, true);
  atclient_atkey_metadata_set_ttl(metadata, 10000);

  atclient_notify_params notify_params;
  atclient_notify_params_init(&notify_params);
  atclient_notify_params_set_atkey(&notify_params, &pingkey);
  atclient_notify_params_set_operation(&notify_params, ATCLIENT_NOTIFY_OPERATION_UPDATE);
  atclient_notify_params_set_value(&notify_params, _ping_response);

  res = _notifyWithRetry(worker, &notify_params, NULL);
  if (res != 0) {
    NOPORTS_LOGE(TAG, "Failed to send ping response to %s", message->notification->from);
  } else {
    NOPORTS_LOGI(TAG, "Sent ping response to %s", message->notification->from);
  }

  if (_config.on_ping) {
    _config.on_ping(message->notification->from);
  }

  atclient_notify_params_free(&notify_params);
  atclient_atkey_free(&pingkey);
}

// ============================================================================
// Private: NPT Request handler (from handle_npt_request.c)
// ============================================================================

void NoPortsDaemon::_handleNptRequest(void *msg) {
  atclient_monitor_message *message = (atclient_monitor_message *)msg;
  atclient *worker = (atclient *)_worker_ctx;
  atchops_rsa_key_private_key *skey = (atchops_rsa_key_private_key *)_signing_key;
  int res = 0;

  // Extract envelope from notification
  if (!atclient_atnotification_is_decrypted_value_initialized(message->notification) ||
      message->notification->decrypted_value == NULL) {
    NOPORTS_LOGE(TAG, "NPT: no decrypted value");
    return;
  }

  cJSON *envelope = cJSON_Parse(message->notification->decrypted_value);
  if (envelope == NULL) {
    NOPORTS_LOGE(TAG, "NPT: failed to parse envelope JSON");
    return;
  }

  // Verify envelope signature
  char *requesting_atsign = message->notification->from;
  if (!_verifyEnvelopeSignature(envelope, requesting_atsign)) {
    NOPORTS_LOGE(TAG, "NPT: envelope signature verification failed");
    cJSON_Delete(envelope);
    return;
  }

  // Verify contents
  if (!_verifyEnvelopeContents(envelope, 1 /* payload_type_npt */)) {
    NOPORTS_LOGE(TAG, "NPT: invalid envelope contents");
    cJSON_Delete(envelope);
    return;
  }

  cJSON *payload = cJSON_GetObjectItem(envelope, "payload");

  // Check permitopen
  cJSON *requested_host = cJSON_GetObjectItem(payload, "requestedHost");
  cJSON *requested_port = cJSON_GetObjectItem(payload, "requestedPort");

  if (requested_host && requested_port && _config.permitopen_count > 0) {
    const char *rhost = cJSON_GetStringValue(requested_host);
    uint16_t rport = (uint16_t)cJSON_GetNumberValue(requested_port);

    bool permitted = false;
    for (uint8_t i = 0; i < _config.permitopen_count; i++) {
      bool host_match = (strcmp(_config.permitopen[i].host, "*") == 0) ||
                        (strcmp(_config.permitopen[i].host, rhost) == 0);
      bool port_match = (_config.permitopen[i].port == 0) ||
                        (_config.permitopen[i].port == rport);
      if (host_match && port_match) {
        permitted = true;
        break;
      }
    }

    if (!permitted) {
      NOPORTS_LOGW(TAG, "NPT: request to %s:%d not permitted", rhost, rport);
      cJSON_Delete(envelope);
      return;
    }
  }

  // Extract RVD connection info
  cJSON *rvd_host = cJSON_GetObjectItem(payload, "rvdHost");
  cJSON *rvd_port = cJSON_GetObjectItem(payload, "rvdPort");
  cJSON *session_id = cJSON_GetObjectItem(payload, "sessionId");

  if (!rvd_host || !rvd_port || !session_id) {
    NOPORTS_LOGE(TAG, "NPT: missing rvdHost/rvdPort/sessionId");
    cJSON_Delete(envelope);
    return;
  }

  // Check if we have a free relay slot
  int slot = _findFreeRelaySlot();
  if (slot < 0) {
    NOPORTS_LOGE(TAG, "NPT: no free relay slots (max %d)", NOPORTS_MAX_RELAYS);
    cJSON_Delete(envelope);
    return;
  }

  // Setup relay config
  NoPortsRelayConfig relay_cfg;
  noports_relay_config_init(&relay_cfg);

  relay_cfg.rvd_host = cJSON_GetStringValue(rvd_host);
  relay_cfg.rvd_port = (uint16_t)cJSON_GetNumberValue(rvd_port);
  relay_cfg.local_host = cJSON_GetStringValue(requested_host);
  relay_cfg.local_port = (uint16_t)cJSON_GetNumberValue(requested_port);
  relay_cfg.multi = true;

  // Parse idle timeout from NPT request (sent in milliseconds by client)
  cJSON *timeout_item = cJSON_GetObjectItem(payload, "timeout");
  if (cJSON_IsNumber(timeout_item)) {
    uint32_t timeout_ms = (uint32_t)cJSON_GetNumberValue(timeout_item);
    relay_cfg.idle_timeout_ms = timeout_ms;
    NOPORTS_LOGI(TAG, "NPT: client requested timeout %u ms", (unsigned)timeout_ms);
  } else {
    relay_cfg.idle_timeout_ms = 0; // use default
  }

  strncpy(relay_cfg.session_id, cJSON_GetStringValue(session_id),
          sizeof(relay_cfg.session_id) - 1);

  // Handle RVD authentication
  bool authenticate_to_rvd = cJSON_IsTrue(cJSON_GetObjectItem(payload, "authenticateToRvd"));
  if (authenticate_to_rvd) {
    relay_cfg.rv_auth = true;

    // Create auth string (from handler_commons.c create_rvd_auth_string)
    cJSON *client_nonce = cJSON_GetObjectItem(payload, "clientNonce");
    cJSON *rvd_nonce = cJSON_GetObjectItem(payload, "rvdNonce");

    if (cJSON_IsString(client_nonce) && cJSON_IsString(rvd_nonce)) {
      cJSON *auth_payload = cJSON_CreateObject();
      cJSON_AddItemReferenceToObject(auth_payload, "sessionId", session_id);
      cJSON_AddItemReferenceToObject(auth_payload, "clientNonce", client_nonce);
      cJSON_AddItemReferenceToObject(auth_payload, "rvdNonce", rvd_nonce);

      cJSON *auth_envelope = cJSON_CreateObject();
      cJSON_AddItemReferenceToObject(auth_envelope, "payload", auth_payload);

      char *signing_input = cJSON_PrintUnformatted(auth_payload);
      unsigned char signature[256];
      memset(signature, 0, 256);

      res = atchops_rsa_sign(skey, ATCHOPS_MD_SHA256,
                             (unsigned char *)signing_input,
                             strlen(signing_input), signature);
      cJSON_free(signing_input);

      if (res == 0) {
        char b64sig[384];
        memset(b64sig, 0, 384);
        size_t sig_len;
        res = atchops_base64_encode(signature, 256, b64sig, 384, &sig_len);
        if (res == 0) {
          cJSON_AddStringToObject(auth_envelope, "signature", b64sig);
          cJSON_AddStringToObject(auth_envelope, "hashingAlgo", "sha256");
          cJSON_AddStringToObject(auth_envelope, "signingAlgo", "rsa2048");
          relay_cfg.rvd_auth_string = cJSON_PrintUnformatted(auth_envelope);
        }
      }

      cJSON_Delete(auth_payload);
      cJSON_Delete(auth_envelope);
    }
  }

  // Handle E2EE (from handler_commons.c setup_rvd_session_encryption)
  // Daemon generates TWO AES key/IV pairs (C2D + D2C), encrypts them with
  // client's ephemeral RSA PK, sends encrypted versions in success response,
  // and uses plaintext versions for control channel encryption.
  // Twin-key mode: C2D for Client→Daemon, D2C for Daemon→Client
  bool encrypt_rvd_traffic = cJSON_IsTrue(cJSON_GetObjectItem(payload, "encryptRvdTraffic"));
  char *session_aes_key_b64 = NULL;
  char *session_iv_b64 = NULL;
  char *session_aes_key_d2c_b64 = NULL;
  char *session_iv_d2c_b64 = NULL;

  if (encrypt_rvd_traffic) {
    relay_cfg.rv_e2ee = true;

    // Generate C2D session AES key and IV
    unsigned char aes_key[32], iv[16];
    memset(aes_key, 0, 32);
    memset(iv, 0, 16);
    atchops_aes_generate_key(aes_key, ATCHOPS_AES_256);
    atchops_iv_generate(iv);

    // Generate D2C session AES key and IV
    unsigned char aes_key_d2c[32], iv_d2c[16];
    memset(aes_key_d2c, 0, 32);
    memset(iv_d2c, 0, 16);
    atchops_aes_generate_key(aes_key_d2c, ATCHOPS_AES_256);
    atchops_iv_generate(iv_d2c);

    // Base64 encode plaintext keys for relay's control channel
    relay_cfg.session_aes_key = (unsigned char *)malloc(49);
    relay_cfg.session_iv = (unsigned char *)malloc(25);
    relay_cfg.session_aes_key_d2c = (unsigned char *)malloc(49);
    relay_cfg.session_iv_d2c = (unsigned char *)malloc(25);

    if (relay_cfg.session_aes_key && relay_cfg.session_iv &&
        relay_cfg.session_aes_key_d2c && relay_cfg.session_iv_d2c) {
      size_t len;
      atchops_base64_encode(aes_key, 32, (char *)relay_cfg.session_aes_key, 49, &len);
      atchops_base64_encode(iv, 16, (char *)relay_cfg.session_iv, 25, &len);
      atchops_base64_encode(aes_key_d2c, 32, (char *)relay_cfg.session_aes_key_d2c, 49, &len);
      atchops_base64_encode(iv_d2c, 16, (char *)relay_cfg.session_iv_d2c, 25, &len);

      NOPORTS_LOGI(TAG, "NPT: generated twin session keys (C2D + D2C)");

      // Encrypt the session keys with client's ephemeral RSA public key
      cJSON *client_pk = cJSON_GetObjectItem(payload, "clientEphemeralPK");
      cJSON *client_pk_type = cJSON_GetObjectItem(payload, "clientEphemeralPKType");

      if (client_pk && client_pk_type &&
          strcmp(cJSON_GetStringValue(client_pk_type), "rsa2048") == 0) {

        atchops_rsa_key_public_key ephem_pk;
        atchops_rsa_key_public_key_init(&ephem_pk);

        char *pk_str = cJSON_GetStringValue(client_pk);
        res = atchops_rsa_key_populate_public_key(&ephem_pk, pk_str, strlen(pk_str));

        if (res == 0) {
          unsigned char enc_buf[256];

          // Encrypt C2D AES key
          res = atchops_rsa_encrypt(&ephem_pk, relay_cfg.session_aes_key,
                                    strlen((char *)relay_cfg.session_aes_key), enc_buf);
          if (res == 0) {
            session_aes_key_b64 = (char *)malloc(384);
            if (session_aes_key_b64) {
              size_t b64_len;
              atchops_base64_encode(enc_buf, 256, session_aes_key_b64, 384, &b64_len);
            }
          }

          // Encrypt C2D IV
          res = atchops_rsa_encrypt(&ephem_pk, relay_cfg.session_iv,
                                    strlen((char *)relay_cfg.session_iv), enc_buf);
          if (res == 0) {
            session_iv_b64 = (char *)malloc(384);
            if (session_iv_b64) {
              size_t b64_len;
              atchops_base64_encode(enc_buf, 256, session_iv_b64, 384, &b64_len);
            }
          }

          // Encrypt D2C AES key
          res = atchops_rsa_encrypt(&ephem_pk, relay_cfg.session_aes_key_d2c,
                                    strlen((char *)relay_cfg.session_aes_key_d2c), enc_buf);
          if (res == 0) {
            session_aes_key_d2c_b64 = (char *)malloc(384);
            if (session_aes_key_d2c_b64) {
              size_t b64_len;
              atchops_base64_encode(enc_buf, 256, session_aes_key_d2c_b64, 384, &b64_len);
            }
          }

          // Encrypt D2C IV
          res = atchops_rsa_encrypt(&ephem_pk, relay_cfg.session_iv_d2c,
                                    strlen((char *)relay_cfg.session_iv_d2c), enc_buf);
          if (res == 0) {
            session_iv_d2c_b64 = (char *)malloc(384);
            if (session_iv_d2c_b64) {
              size_t b64_len;
              atchops_base64_encode(enc_buf, 256, session_iv_d2c_b64, 384, &b64_len);
            }
          }
        }

        atchops_rsa_key_public_key_free(&ephem_pk);
      }
    }
  }

  // Send success response BEFORE starting relay.
  // The relay task allocates ~8KB (6KB stack + buffers), and the TLS send
  // also needs ~16KB for its buffers. On ESP32 with limited heap, doing
  // both concurrently causes malloc failures. Send first, then start relay.
  // The client connects to SRVD after receiving this, so the relay will
  // be ready in time.
  {
    char *identifier = cJSON_GetStringValue(session_id);
    cJSON *res_payload = cJSON_CreateObject();
    cJSON_AddStringToObject(res_payload, "status", "connected");
    cJSON_AddItemReferenceToObject(res_payload, "sessionId", session_id);
    if (session_aes_key_b64) {
      cJSON_AddStringToObject(res_payload, "sessionAESKey", session_aes_key_b64);
    }
    if (session_iv_b64) {
      cJSON_AddStringToObject(res_payload, "sessionIV", session_iv_b64);
    }
    if (session_aes_key_d2c_b64) {
      cJSON_AddStringToObject(res_payload, "aesKeyD2C", session_aes_key_d2c_b64);
    }
    if (session_iv_d2c_b64) {
      cJSON_AddStringToObject(res_payload, "ivD2C", session_iv_d2c_b64);
    }

    cJSON *res_envelope = cJSON_CreateObject();
    cJSON_AddItemToObject(res_envelope, "payload", res_payload);

    // Sign the response
    char *signing_input = cJSON_PrintUnformatted(res_payload);
    unsigned char signature[256];
    memset(signature, 0, 256);

    res = atchops_rsa_sign(skey, ATCHOPS_MD_SHA256,
                           (unsigned char *)signing_input,
                           strlen(signing_input), signature);
    cJSON_free(signing_input);

    if (res == 0) {
      char b64sig[384];
      memset(b64sig, 0, 384);
      size_t sig_len;
      atchops_base64_encode(signature, 256, b64sig, 384, &sig_len);

      cJSON_AddStringToObject(res_envelope, "signature", b64sig);
      cJSON_AddStringToObject(res_envelope, "hashingAlgo", "sha256");
      cJSON_AddStringToObject(res_envelope, "signingAlgo", "rsa2048");

      char *res_value = cJSON_PrintUnformatted(res_envelope);

      // Send notification
      atclient_atkey res_atkey;
      atclient_atkey_init(&res_atkey);

      size_t klen = strlen(identifier) + strlen(_config.device_name) + 2;
      char *kname = (char *)malloc(klen);
      if (kname) {
        snprintf(kname, klen, "%s.%s", identifier, _config.device_name);

        atclient_atkey_create_shared_key(&res_atkey, kname, _config.atsign,
                                         requesting_atsign, NOPORTS_NS);

        atclient_atkey_metadata *meta = &res_atkey.metadata;
        atclient_atkey_metadata_set_is_public(meta, false);
        atclient_atkey_metadata_set_is_encrypted(meta, true);
        atclient_atkey_metadata_set_ttl(meta, 10000);

        atclient_notify_params nparams;
        atclient_notify_params_init(&nparams);
        atclient_notify_params_set_atkey(&nparams, &res_atkey);
        atclient_notify_params_set_value(&nparams, res_value);
        atclient_notify_params_set_operation(&nparams, ATCLIENT_NOTIFY_OPERATION_UPDATE);

        int nret = _notifyWithRetry(worker, &nparams, NULL);
        if (nret != 0) {
          NOPORTS_LOGE(TAG, "NPT: failed to send success response to %s", requesting_atsign);
        } else {
          NOPORTS_LOGI(TAG, "NPT: sent success response to %s", requesting_atsign);
        }

        atclient_notify_params_free(&nparams);
        free(kname);
      }

      atclient_atkey_free(&res_atkey);
      if (res_value) cJSON_free(res_value);
    }

    cJSON_Delete(res_envelope);
  }

  // Start the relay AFTER sending the success response.
  // This ensures TLS buffers from the notification send are freed before
  // the relay allocates its task stack and buffers.
  res = noports_relay_start(&_relays[slot], &relay_cfg);
  if (res != 0) {
    NOPORTS_LOGE(TAG, "NPT: failed to start relay");
    cJSON_Delete(envelope);
    if (session_aes_key_b64) free(session_aes_key_b64);
    if (session_iv_b64) free(session_iv_b64);
    if (session_aes_key_d2c_b64) free(session_aes_key_d2c_b64);
    if (session_iv_d2c_b64) free(session_iv_d2c_b64);
    return;
  }

  if (_config.on_tunnel_open) {
    _config.on_tunnel_open(
      cJSON_GetStringValue(requested_host),
      (uint16_t)cJSON_GetNumberValue(requested_port),
      relay_cfg.session_id);
  }

  if (session_aes_key_b64) free(session_aes_key_b64);
  if (session_iv_b64) free(session_iv_b64);
  if (session_aes_key_d2c_b64) free(session_aes_key_d2c_b64);
  if (session_iv_d2c_b64) free(session_iv_d2c_b64);
  cJSON_Delete(envelope);
}

// ============================================================================
// Private: Graceful shutdown
// ============================================================================

void NoPortsDaemon::_handleGracefulShutdown() {
  _should_run = false;
}

// ============================================================================
// Private: Envelope verification (from handler_commons.c)
// ============================================================================

bool NoPortsDaemon::_verifyEnvelopeSignature(void *env, const char *from_atsign) {
  cJSON *envelope = (cJSON *)env;
  atclient *worker = (atclient *)_worker_ctx;

  cJSON *signature = cJSON_GetObjectItem(envelope, "signature");
  cJSON *hashing_algo = cJSON_GetObjectItem(envelope, "hashingAlgo");
  cJSON *signing_algo = cJSON_GetObjectItem(envelope, "signingAlgo");
  cJSON *payload = cJSON_GetObjectItem(envelope, "payload");

  if (!cJSON_IsString(signature) || !cJSON_IsString(hashing_algo) ||
      !cJSON_IsString(signing_algo) || !cJSON_IsObject(payload)) {
    NOPORTS_LOGE(TAG, "Invalid envelope format for signature verification");
    return false;
  }

  // Get the requester's public key
  atclient_atkey pubkey;
  atclient_atkey_init(&pubkey);

  int res = atclient_atkey_create_public_key(&pubkey, "publickey",
                                             (char *)from_atsign, NULL);
  if (res != 0) {
    atclient_atkey_free(&pubkey);
    return false;
  }

  char *pk_buffer = NULL;
  res = atclient_get_public_key(worker, &pubkey, &pk_buffer, NULL);
  atclient_atkey_free(&pubkey);

  if (res != 0 || pk_buffer == NULL) {
    NOPORTS_LOGE(TAG, "Failed to get public key for %s", from_atsign);
    return false;
  }

  atchops_rsa_key_public_key requester_pk;
  atchops_rsa_key_public_key_init(&requester_pk);

  res = atchops_rsa_key_populate_public_key(&requester_pk, pk_buffer, strlen(pk_buffer));
  if (res != 0) {
    free(pk_buffer);
    return false;
  }

  // Decode the signature
  char *sig_str = cJSON_GetStringValue(signature);
  size_t sig_dec_len = 0;
  res = atchops_base64_decode(sig_str, strlen(sig_str),
                              (unsigned char *)pk_buffer, strlen(pk_buffer),
                              &sig_dec_len);
  if (res != 0) {
    NOPORTS_LOGE(TAG, "Failed to decode signature");
    free(pk_buffer);
    atchops_rsa_key_public_key_free(&requester_pk);
    return false;
  }

  // Verify
  char *payload_str = cJSON_PrintUnformatted(payload);
  char *hash_algo = cJSON_GetStringValue(hashing_algo);
  char *sign_algo = cJSON_GetStringValue(signing_algo);

  bool verified = false;

  if (strcmp(hash_algo, "sha256") == 0 && strcmp(sign_algo, "rsa2048") == 0) {
    res = atchops_rsa_verify(&requester_pk, ATCHOPS_MD_SHA256,
                             (unsigned char *)payload_str, strlen(payload_str),
                             (unsigned char *)pk_buffer);
    verified = (res == 0);
  }

  cJSON_free(payload_str);
  free(pk_buffer);
  atchops_rsa_key_public_key_free(&requester_pk);

  if (!verified) {
    NOPORTS_LOGE(TAG, "Envelope signature verification failed");
  }

  return verified;
}

bool NoPortsDaemon::_verifyEnvelopeContents(void *env, int payload_type) {
  cJSON *envelope = (cJSON *)env;

  cJSON *payload = cJSON_GetObjectItem(envelope, "payload");
  if (!cJSON_IsObject(payload)) return false;
  if (!cJSON_IsString(cJSON_GetObjectItem(envelope, "signature"))) return false;
  if (!cJSON_IsString(cJSON_GetObjectItem(envelope, "hashingAlgo"))) return false;
  if (!cJSON_IsString(cJSON_GetObjectItem(envelope, "signingAlgo"))) return false;
  if (!cJSON_IsString(cJSON_GetObjectItem(payload, "sessionId"))) return false;

  if (payload_type == 1) { // NPT
    if (!cJSON_IsString(cJSON_GetObjectItem(payload, "rvdHost"))) return false;
    if (!cJSON_IsNumber(cJSON_GetObjectItem(payload, "rvdPort"))) return false;
    if (!cJSON_IsString(cJSON_GetObjectItem(payload, "requestedHost"))) return false;

    cJSON *rp = cJSON_GetObjectItem(payload, "requestedPort");
    if (!cJSON_IsNumber(rp) || cJSON_GetNumberValue(rp) <= 0) return false;
  }

  return true;
}

// ============================================================================
// Private: Relay management
// ============================================================================

int NoPortsDaemon::_findFreeRelaySlot() {
  for (int i = 0; i < NOPORTS_MAX_RELAYS; i++) {
    if (!noports_relay_is_running(&_relays[i]) &&
        _relays[i].state != RELAY_CONNECTING &&
        _relays[i].state != RELAY_AUTHENTICATING) {
      return i;
    }
  }
  return -1;
}

void NoPortsDaemon::_cleanupFinishedRelays() {
  for (int i = 0; i < NOPORTS_MAX_RELAYS; i++) {
    if (_relays[i].state == RELAY_STOPPED || _relays[i].state == RELAY_ERROR) {
      if (_relays[i].task_handle == NULL) {
        if (_config.on_tunnel_close) {
          _config.on_tunnel_close(_relays[i].config.session_id);
        }
        _relays[i].state = RELAY_IDLE;
        _relays[i].bytes_in = 0;
        _relays[i].bytes_out = 0;
        _relays[i].start_ms = 0;
        memset(&_relays[i].config, 0, sizeof(NoPortsRelayConfig));
      }
    }
  }
}

// ============================================================================
// Private: Reconnection
// ============================================================================

bool NoPortsDaemon::_reconnectMonitor() {
  // Exponential backoff: 5s, 10s, 20s, 30s, 30s, ...
  if (_reconnect_failures > 0) {
    unsigned long backoff_ms = 5000UL << (_reconnect_failures - 1);
    if (backoff_ms > 30000) backoff_ms = 30000;
    NOPORTS_LOGI(TAG, "Reconnect backoff: %lu ms (attempt %d, free heap: %u)",
                 backoff_ms, _reconnect_failures + 1,
                 (unsigned)esp_get_free_heap_size());
    delay(backoff_ms);
  }

  NOPORTS_LOGI(TAG, "Reconnecting monitor...");

  atclient *monitor = (atclient *)_monitor_ctx;
  atclient_atkeys *keys = (atclient_atkeys *)_atkeys;

  // Fully tear down the old monitor connection before re-auth
  atclient_monitor_free(monitor);
  atclient_monitor_init(monitor);

  int res = atclient_monitor_pkam_authenticate(
    monitor, _config.atsign, keys,
    (atclient_authenticate_options *)_monitor_options);

  if (res != 0) {
    NOPORTS_LOGE(TAG, "Monitor reconnect auth failed: %d", res);
    if (_reconnect_failures < 255) _reconnect_failures++;
    return false;
  }

  res = atclient_monitor_start(monitor, _monitor_regex);
  if (res != 0) {
    NOPORTS_LOGE(TAG, "Monitor reconnect start failed: %d", res);
    if (_reconnect_failures < 255) _reconnect_failures++;
    return false;
  }

  _reconnect_failures = 0;
  NOPORTS_LOGI(TAG, "Monitor reconnected");
  return true;
}

bool NoPortsDaemon::_reconnectWorker() {
  NOPORTS_LOGI(TAG, "Reconnecting worker...");

  atclient *worker = (atclient *)_worker_ctx;
  atclient_atkeys *keys = (atclient_atkeys *)_atkeys;

  // Fully tear down the old worker connection
  atclient_free(worker);
  atclient_init(worker);

  int res = atclient_pkam_authenticate(
    worker, _config.atsign, keys,
    (atclient_authenticate_options *)_worker_options, NULL);

  if (res != 0) {
    NOPORTS_LOGE(TAG, "Worker reconnect auth failed: %d", res);
    return false;
  }

  NOPORTS_LOGI(TAG, "Worker reconnected");
  return true;
}

int NoPortsDaemon::_notifyWithRetry(void *w, void *np, char **notification_id) {
  atclient *worker = (atclient *)w;
  atclient_notify_params *params = (atclient_notify_params *)np;

  int res = atclient_notify(worker, params, notification_id);
  if (res != 0) {
    NOPORTS_LOGW(TAG, "Notify failed (%d), reconnecting worker and retrying...", res);
    if (_reconnectWorker()) {
      // worker pointer is unchanged (same allocation, re-authenticated)
      res = atclient_notify(worker, params, notification_id);
    }
  }
  return res;
}

// ============================================================================
// Private: Utility
// ============================================================================

void NoPortsDaemon::_setError(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(_last_error, sizeof(_last_error), fmt, args);
  va_end(args);
  NOPORTS_LOGE(TAG, "%s", _last_error);
}
