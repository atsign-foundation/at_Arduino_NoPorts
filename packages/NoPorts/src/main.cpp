/**
 * LoadKeysFromSPIFFS.ino
 *
 * Example showing how to load atKeys from the ESP32 filesystem (SPIFFS/LittleFS)
 * instead of hardcoding them in the sketch.
 *
 * Steps to use:
 *   1. Upload your .atKeys file to the ESP32 SPIFFS partition as "/atkeys.json"
 *      (use the ESP32 Filesystem Uploader plugin or esptool)
 *   2. Flash this sketch
 *   3. The daemon will read and decrypt the keys at boot
 *
 * To upload files to SPIFFS:
 *   - Arduino IDE: Install "ESP32 Sketch Data Upload" plugin, put atkeys.json
 *     in the "data" folder of your sketch, then use Tools > ESP32 Sketch Data Upload
 *   - PlatformIO: Put atkeys.json in the "data" folder, run "pio run -t uploadfs"
 *   - esptool: Use espflash or similar tool
 */

#include <WiFi.h>
#include <NoPorts.h>
#include <esp_system.h>

extern "C" {
  #include "atlogger/atlogger.h"
}

const char *WIFI_SSID      = "JacobMesh";
const char *WIFI_PASSWORD  = "Relax.Here2";
const char *DEVICE_ATSIGN  = "@ssh_1";
const char *DEVICE_NAME    = "esp32";
const char *MANAGER_ATSIGN = "@cconstab";

NoPortsDaemon npDaemon;

// ---------------------------------------------------------------------------
// Health monitoring thresholds
// ---------------------------------------------------------------------------
#define HEAP_CRITICAL_THRESHOLD   20000   // bytes – restart if free heap below this
#define HEAP_WARNING_THRESHOLD    40000   // bytes – log warning
#define HEAP_LOG_INTERVAL_MS      30000   // log heap stats every 30s
#define WIFI_CHECK_INTERVAL_MS    10000   // check WiFi every 10s
#define WIFI_RECONNECT_TIMEOUT_MS 30000   // give WiFi 30s to reconnect before restart
#define DAEMON_RESTART_DELAY_MS   5000    // wait before ESP.restart()

static unsigned long lastHeapLogTime   = 0;
static unsigned long lastWifiCheckTime = 0;
static uint32_t      loopIterations    = 0;
static uint32_t      minFreeHeap       = UINT32_MAX;

/**
 * Log heap statistics periodically.
 * Tracks minimum free heap since boot to spot slow leaks.
 */
void logHeapStats() {
  unsigned long now = millis();
  uint32_t freeHeap = esp_get_free_heap_size();
  uint32_t minEver  = esp_get_minimum_free_heap_size();

  if (freeHeap < minFreeHeap) minFreeHeap = freeHeap;

  if ((now - lastHeapLogTime) >= HEAP_LOG_INTERVAL_MS) {
    lastHeapLogTime = now;
    Serial.printf("[health] Free heap: %u  Min ever: %u  Stack HWM: %u  Uptime: %lus  Loops: %u\n",
                  freeHeap, minEver,
                  (unsigned)uxTaskGetStackHighWaterMark(NULL),
                  now / 1000, loopIterations);

    if (freeHeap < HEAP_WARNING_THRESHOLD) {
      Serial.printf("[health] WARNING: Free heap %u below warning threshold %u\n",
                    freeHeap, HEAP_WARNING_THRESHOLD);
    }
  }

  // Critical heap — restart to recover
  if (freeHeap < HEAP_CRITICAL_THRESHOLD) {
    Serial.printf("[health] CRITICAL: Free heap %u below %u — restarting in %ds\n",
                  freeHeap, HEAP_CRITICAL_THRESHOLD, DAEMON_RESTART_DELAY_MS / 1000);
    Serial.flush();
    delay(DAEMON_RESTART_DELAY_MS);
    ESP.restart();
  }
}

/**
 * Ensure WiFi stays connected. If it drops, try to reconnect.
 * If reconnection fails for too long, restart the device.
 */
static unsigned long wifiLostSince = 0;

void checkWiFi() {
  unsigned long now = millis();
  if ((now - lastWifiCheckTime) < WIFI_CHECK_INTERVAL_MS) return;
  lastWifiCheckTime = now;

  if (WiFi.status() == WL_CONNECTED) {
    if (wifiLostSince != 0) {
      Serial.printf("[health] WiFi reconnected after %lus\n",
                    (now - wifiLostSince) / 1000);
      wifiLostSince = 0;
    }
    return;
  }

  // WiFi is down
  if (wifiLostSince == 0) {
    wifiLostSince = now;
    Serial.println("[health] WiFi disconnected — attempting reconnect");
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  } else if ((now - wifiLostSince) > WIFI_RECONNECT_TIMEOUT_MS) {
    Serial.printf("[health] WiFi down for %lus — restarting device\n",
                  (now - wifiLostSince) / 1000);
    Serial.flush();
    delay(DAEMON_RESTART_DELAY_MS);
    ESP.restart();
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("NoPorts - Loading keys from filesystem");

  // Enable atSDK internal logging so we can see connection errors
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\nWiFi connected: %s\n", WiFi.localIP().toString().c_str());

  // Configure daemon
  NoPortsConfig config;
  noports_config_init(&config);
  config.atsign       = DEVICE_ATSIGN;
  config.device_name  = DEVICE_NAME;
  config.manager_list[0] = MANAGER_ATSIGN;
  config.manager_count   = 1;

  // Load keys from SPIFFS
  int res = noports_keys_load_from_file(&config, "/atkeys.json");
  if (res != 0) {
    Serial.println("ERROR: Failed to load atkeys from SPIFFS!");
    Serial.println("Make sure you've uploaded /atkeys.json to SPIFFS.");
    while (true) { delay(1000); }
  }
  Serial.println("Keys loaded from SPIFFS successfully");

  // Allow tunneling to local web server
  config.permitopen[0] = { "192.168.1.149", 22 };
  config.permitopen[1] = { "192.168.1.149", 2200};
  config.permitopen_count = 2;

  // Start daemon
  if (!npDaemon.begin(config)) {
    Serial.printf("NoPorts failed: %s\n", npDaemon.getLastError());
    while (true) { delay(1000); }
  }
  Serial.println("NoPorts daemon running!");

  // Note: noports_keys_free(&config) should be called if you want to
  // reclaim the memory used by the decrypted keys. But since the daemon
  // has already copied what it needs, it's safe to free here.
  noports_keys_free(&config);
}

void loop() {
  loopIterations++;

  // Health checks — run BEFORE daemon loop so we catch problems early
  checkWiFi();
  logHeapStats();

  // Only run daemon if WiFi is up
  if (WiFi.status() == WL_CONNECTED) {
    npDaemon.loop();
  }

  // Check if daemon fell into error state
  if (!npDaemon.isRunning() && npDaemon.getState() == DAEMON_ERROR) {
    Serial.printf("[health] Daemon in ERROR state: %s — restarting device\n",
                  npDaemon.getLastError());
    Serial.flush();
    delay(DAEMON_RESTART_DELAY_MS);
    ESP.restart();
  }

  delay(10);
}