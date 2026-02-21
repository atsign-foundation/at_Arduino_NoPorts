/**
 * @file main_tft.cpp
 * @brief NoPorts CYD main entry point - TFT_eSPI version (memory-efficient)
 *
 * Boot flow:
 *   1. Init TFT display + touch + LED
 *   2. If previously configured → auto-connect WiFi → load keys → daemon → dashboard
 *   3. If not configured → WiFi screen → enroll screen → dashboard
 *
 * loop():
 *   - Handle touch input
 *   - npDaemon.loop()      (drives NoPorts monitor/relay)
 *   - ui_dashboard_update() (refreshes stats from event queue)
 */

#include <Arduino.h>
#include <LittleFS.h>
#include <NoPorts.h>
#include "esp_bt.h"

extern "C" {
  #include "atlogger/atlogger.h"
}

#include "ui_tft.h"
#include "ui_wifi_tft.h"
#include "ui_enroll_tft.h"
#include "ui_dashboard_tft.h"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static NoPortsDaemon npDaemon;
static bool daemon_running = false;

// Session tracking
static uint32_t _total_tunnels = 0;
static uint32_t _total_pings = 0;

enum AppScreen {
  SCREEN_NONE,
  SCREEN_SPLASH,
  SCREEN_WIFI,
  SCREEN_ENROLL,
  SCREEN_DASHBOARD
};

static AppScreen current_screen = SCREEN_NONE;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static const char *daemon_state_str(NoPortsDaemonState s) {
  switch (s) {
    case DAEMON_UNINITIALIZED:  return "uninit";
    case DAEMON_INITIALIZING:   return "init";
    case DAEMON_AUTHENTICATING: return "auth";
    case DAEMON_MONITORING:     return "running";
    case DAEMON_ERROR:          return "error";
    case DAEMON_STOPPED:        return "stopped";
    default:                    return "?";
  }
}

// ---------------------------------------------------------------------------
// NoPorts callbacks → event queue
// ---------------------------------------------------------------------------

static void on_tunnel_open(const char *host, uint16_t port, const char *session_id) {
  _total_tunnels++;
  char buf[EVENT_TEXT_LEN];
  snprintf(buf, sizeof(buf), "Tunnel %s:%u", host, port);
  ui_event_push(UI_EVT_TUNNEL_OPEN, buf);
}

static void on_tunnel_close(const char *session_id) {
  char buf[EVENT_TEXT_LEN];
  snprintf(buf, sizeof(buf), "Closed [%.8s]", session_id ? session_id : "?");
  ui_event_push(UI_EVT_TUNNEL_CLOSE, buf);
}

static void on_ping(const char *from_atsign) {
  _total_pings++;
  char buf[EVENT_TEXT_LEN];
  snprintf(buf, sizeof(buf), "Ping from %s", from_atsign ? from_atsign : "?");
  ui_event_push(UI_EVT_PING, buf);
}

// ---------------------------------------------------------------------------
// Start the NoPorts daemon
// ---------------------------------------------------------------------------

static void _do_reset();

static bool start_daemon() {
  // These MUST be static — NoPortsDaemon::begin() stores pointers to them
  // via memcpy, so they must outlive the function call.
  static String atsign  = ui_load_string(NVS_KEY_ATSIGN);
  static String device  = ui_load_string(NVS_KEY_DEVICE);
  static String manager = ui_load_string(NVS_KEY_MANAGER);

  if (atsign.length() == 0 || device.length() == 0) {
    Serial.println("[main] Missing atSign/device in NVS");
    return false;
  }

  NoPortsConfig config;
  noports_config_init(&config);
  config.atsign          = atsign.c_str();
  config.device_name     = device.c_str();
  config.manager_list[0] = manager.c_str();
  config.manager_count   = 1;

  // Callbacks
  config.on_tunnel_open  = on_tunnel_open;
  config.on_tunnel_close = on_tunnel_close;
  config.on_ping         = on_ping;

  // Load keys from LittleFS
  if (!LittleFS.begin(true)) {
    Serial.println("[main] LittleFS mount failed");
    return false;
  }

  int res = noports_keys_load_from_file(&config, ATKEYS_PATH);
  if (res != 0) {
    Serial.printf("[main] Failed to load keys from %s (err=%d)\n", ATKEYS_PATH, res);
    return false;
  }
  Serial.println("[main] Keys loaded from LittleFS");

  if (!npDaemon.begin(config)) {
    Serial.printf("[main] Daemon begin failed: %s\n", npDaemon.getLastError());
    noports_keys_free(&config);
    return false;
  }

  noports_keys_free(&config);
  daemon_running = true;
  Serial.println("[main] NoPorts daemon running!");
  
  // Set LED to cyan (running)
  ui_load_led_color();
  
  return true;
}

// ---------------------------------------------------------------------------
// Reset device: delete atKeys, clear NVS config, reboot
// ---------------------------------------------------------------------------

static void _do_reset() {
  Serial.println("[main] RESET requested — wiping credentials");
  
  // Stop daemon if running
  if (daemon_running) {
    npDaemon.stop();
    daemon_running = false;
  }
  
  // Delete atKeys from LittleFS
  if (LittleFS.begin(true)) {
    if (LittleFS.exists(ATKEYS_PATH)) {
      LittleFS.remove(ATKEYS_PATH);
      Serial.println("[main] Deleted atKeys file");
    }
  }
  
  // Clear enrollment config from NVS
  ui_save_string(NVS_KEY_ATSIGN, "");
  ui_save_string(NVS_KEY_DEVICE, "");
  ui_save_string(NVS_KEY_MANAGER, "");
  ui_set_configured(false);
  
  Serial.println("[main] NVS cleared — rebooting...");
  
  // Show reset message
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  tft.setTextColor(COLOR_ERROR);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(1);
  tft.drawString("Device Reset", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 20, 4);
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.drawString("Rebooting...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);
  
  delay(2000);
  ESP.restart();
}

// ---------------------------------------------------------------------------
// Screen transitions
// ---------------------------------------------------------------------------

static void sync_ntp_time() {
  Serial.println("[NTP] Syncing time...");
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  struct tm timeinfo;
  int retries = 0;
  while (!getLocalTime(&timeinfo, 1000) && retries < 10) {
    retries++;
    Serial.printf("[NTP] Waiting for time... (%d/10)\n", retries);
  }
  
  if (retries < 10) {
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &timeinfo);
    Serial.printf("[NTP] Time set: %s\n", buf);
  } else {
    Serial.println("[NTP] WARNING: Failed to get time");
  }
}

static void _show_daemon_error() {
  // Show error screen with retry/reset options
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  tft.setTextColor(COLOR_ERROR);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(1);
  tft.drawString("Daemon Start Failed", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 40, 4);
  
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.drawString("PKAM auth failed - keys may be invalid", TFT_WIDTH / 2, TFT_HEIGHT / 2, 2);
  tft.drawString("Tap screen to reset and re-enroll", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 25, 2);
  
  current_screen = SCREEN_NONE;  // Special state: any touch triggers reset
  Serial.println("[main] Daemon failed - waiting for touch to reset");
}

static void _on_enrolled() {
  if (start_daemon()) {
    current_screen = SCREEN_DASHBOARD;
    ui_dashboard_create(_do_reset);
  } else {
    _show_daemon_error();
  }
}

static void on_wifi_connected() {
  sync_ntp_time();
  
  if (ui_is_configured()) {
    // Already enrolled – start daemon and go to dashboard
    if (start_daemon()) {
      current_screen = SCREEN_DASHBOARD;
      ui_dashboard_create(_do_reset);
    } else {
      // Keys exist but auth failed – show error with reset option
      _show_daemon_error();
    }
  } else {
    // First run – show enrollment
    current_screen = SCREEN_ENROLL;
    ui_enroll_create(_on_enrolled);
  }
}

static void show_splash() {
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  
  // Show NoPorts logo/title
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(1);
  tft.drawString("NoPorts CYD", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 30, 4);
  
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextSize(1);
  tft.drawString("Initializing...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);
  
  delay(1500);
}

// ---------------------------------------------------------------------------
// setup()
// ---------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n==============================");
  Serial.println("  NoPorts CYD - TFT_eSPI Mode");
  Serial.println("  Memory-Optimized Version");
  Serial.println("==============================\n");

  // Release Bluetooth controller memory — we never use BT (~30KB heap savings)
  esp_bt_controller_mem_release(ESP_BT_MODE_BTDM);
  Serial.printf("[main] Heap after BT release: %u bytes\n", ESP.getFreeHeap());

  // Enable at_client logging
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // Initialize TFT display and touch
  ui_tft_init();
  
  // Run touch calibration on first boot
  if (!ui_touch_is_calibrated()) {
    ui_touch_calibrate();
  }
  
  // Show splash screen
  current_screen = SCREEN_SPLASH;
  show_splash();

  // Check for saved WiFi credentials
  String ssid = ui_load_string(NVS_KEY_SSID);
  
  if (ssid.length() > 0) {
    // Try auto-connect
    TFT_eSPI &tft = ui_get_tft();
    tft.fillScreen(COLOR_BG_DARK);
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextDatum(MC_DATUM);
    tft.setTextSize(1);
    tft.drawString("Connecting to WiFi...", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 10, 2);
    tft.setTextColor(COLOR_TEXT_GREY);
    tft.drawString(ssid.c_str(), TFT_WIDTH / 2, TFT_HEIGHT / 2 + 15, 2);
    
    if (ui_wifi_auto_connect(10000)) {
      Serial.println("[main] Auto-connected to WiFi");
      ui_set_led(false, false, true);  // Blue = connected
      delay(500);
      on_wifi_connected();
    } else {
      Serial.println("[main] Auto-connect failed - showing WiFi setup");
      current_screen = SCREEN_WIFI;
      ui_wifi_create(on_wifi_connected);
    }
  } else {
    // No saved WiFi - show setup
    Serial.println("[main] No saved WiFi - showing setup");
    current_screen = SCREEN_WIFI;
    ui_wifi_create(on_wifi_connected);
  }
  
  Serial.printf("[main] Free heap: %u bytes\n", ESP.getFreeHeap());
}

// ---------------------------------------------------------------------------
// loop()
// ---------------------------------------------------------------------------

void loop() {
  // Handle touch input
  int16_t tx, ty;
  if (ui_touch_read(&tx, &ty)) {
    switch (current_screen) {
      case SCREEN_WIFI:
        ui_wifi_handle_touch(tx, ty);
        break;
        
      case SCREEN_ENROLL:
        ui_enroll_handle_touch(tx, ty);
        break;
        
      case SCREEN_DASHBOARD:
        ui_dashboard_handle_touch(tx, ty);
        break;
        
      case SCREEN_NONE:
        // Error screen – any touch triggers reset
        _do_reset();
        break;
        
      default:
        break;
    }
  }
  
  // Update current screen
  switch (current_screen) {
    case SCREEN_WIFI:
      ui_wifi_update();
      break;
      
    case SCREEN_ENROLL:
      ui_enroll_update();
      ui_enroll_process_events();
      break;
      
    case SCREEN_DASHBOARD:
      // Drive NoPorts daemon
      if (daemon_running && npDaemon.isRunning()) {
        npDaemon.loop();
        
        // Update dashboard periodically
        static uint32_t last_update = 0;
        if (millis() - last_update > 500) {
          last_update = millis();
          ui_dashboard_update(npDaemon.getActiveRelayCount(),
                            daemon_state_str(npDaemon.getState()),
                            _total_tunnels, _total_pings);
        }
      }
      break;
      
    default:
      break;
  }
  
  delay(10);  // Reduced from 5ms to save CPU
}
