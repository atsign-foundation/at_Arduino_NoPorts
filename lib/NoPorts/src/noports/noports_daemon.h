/**
 * @file noports_daemon.h
 * @brief Main NoPorts daemon class for Arduino/ESP32
 *
 * This is the primary interface. It mirrors the flow of main.c and daemon.c
 * from the C sshnpd, adapted for Arduino's setup()/loop() paradigm.
 *
 * Usage:
 *   1. Create a NoPortsDaemon instance
 *   2. Configure it with a NoPortsConfig
 *   3. Call begin() in setup() – this authenticates and starts monitoring
 *   4. Call loop() in loop() – this processes incoming notifications
 *   5. Optionally call stop() to shut down
 */

#ifndef NOPORTS_DAEMON_H
#define NOPORTS_DAEMON_H

#include <Arduino.h>
#include "noports_config.h"
#include "noports_relay.h"

// Maximum concurrent relays (limited by ESP32 memory/sockets)
#define NOPORTS_MAX_RELAYS 4

/**
 * @brief NoPorts daemon states
 */
enum NoPortsDaemonState {
  DAEMON_UNINITIALIZED,
  DAEMON_INITIALIZING,
  DAEMON_AUTHENTICATING,
  DAEMON_MONITORING,
  DAEMON_ERROR,
  DAEMON_STOPPED,
};

/**
 * @brief The main daemon class
 *
 * Encapsulates all the global state from the C sshnpd (atclient, monitor,
 * signing keys, etc.) into a single class suitable for Arduino.
 */
class NoPortsDaemon {
public:
  NoPortsDaemon();
  ~NoPortsDaemon();

  /**
   * @brief Initialize and start the daemon
   *
   * Performs the equivalent of sshnpd main():
   *   1. Validates config
   *   2. Loads/populates atKeys
   *   3. PKAM authenticates the monitor connection
   *   4. PKAM authenticates the worker connection
   *   5. Publishes device info (unless hide=true)
   *   6. Starts monitoring for notifications
   *
   * @param config Configuration (copied internally)
   * @return true on success, false on failure
   */
  bool begin(const NoPortsConfig &config);

  /**
   * @brief Process one iteration of the monitor loop
   *
   * Call this from Arduino's loop(). It checks for incoming notifications
   * and dispatches handlers (ping, npt_request, etc.)
   *
   * This is non-blocking with a configurable timeout. It is the equivalent
   * of one iteration of main_loop() from daemon.c.
   */
  void loop();

  /**
   * @brief Gracefully stop the daemon
   */
  void stop();

  /**
   * @brief Check if the daemon is running
   */
  bool isRunning() const;

  /**
   * @brief Get current daemon state
   */
  NoPortsDaemonState getState() const;

  /**
   * @brief Get number of active relays
   */
  uint8_t getActiveRelayCount() const;

  /**
   * @brief Get aggregate throughput across all active relays
   * @param bytes_in  Total bytes RVD->local (downloaded)
   * @param bytes_out Total bytes local->RVD (uploaded)
   */
  void getThroughput(uint32_t &bytes_in, uint32_t &bytes_out) const;

  /**
   * @brief Get the last error message
   */
  const char* getLastError() const;

private:
  // Daemon state
  NoPortsDaemonState _state;
  NoPortsConfig      _config;
  volatile bool      _should_run;
  char               _last_error[128];

  // atProtocol handles — stored as opaque pointers so the header
  // doesn't pull in the full atSDK type definitions.
  // The .cpp file casts these to the proper types.
  void *_monitor_ctx;       // atclient (monitor)
  void *_worker_ctx;        // atclient (worker)
  void *_atkeys;            // atclient_atkeys
  void *_signing_key;       // atchops_rsa_key_private_key
  void *_monitor_options;   // atclient_authenticate_options
  void *_worker_options;    // atclient_authenticate_options

  // Ping response (pre-built JSON string)
  char *_ping_response;

  // Monitor regex
  char *_monitor_regex;

  // Root server
  char   _root_host[254];
  uint16_t _root_port;

  // Active relays
  NoPortsRelay _relays[NOPORTS_MAX_RELAYS];
  uint8_t      _relay_count;

  // Timeout tracking
  uint32_t _timeout_counter;
  uint8_t  _reconnect_failures;   // consecutive monitor reconnect failures (for backoff)

  // Internal methods (mirror the C sshnpd functions)
  bool _authenticate();
  bool _startMonitor();
  bool _publishDeviceInfo();
  void _buildPingResponse();

  // Notification handlers
  void _handleNotification(void *message); // atclient_monitor_message*
  void _handlePing(void *message);
  void _handleNptRequest(void *message);
  void _handleGracefulShutdown();

  // Relay management
  int  _findFreeRelaySlot();
  void _cleanupFinishedRelays();

  // Reconnection
  bool _reconnectMonitor();
  bool _reconnectWorker();

  // Notify with automatic worker reconnect on failure
  int _notifyWithRetry(void *worker, void *notify_params, char **notification_id);

  // Envelope verification
  bool _verifyEnvelopeSignature(void *envelope, const char *from_atsign);
  bool _verifyEnvelopeContents(void *envelope, int payload_type);

  // Utility
  void _setError(const char *fmt, ...);
};

#endif // NOPORTS_DAEMON_H
