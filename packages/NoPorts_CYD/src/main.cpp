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
#include <WiFi.h>
#include <NoPorts.h>
#include "esp_bt.h"

extern "C" {
  #include "atlogger/atlogger.h"
}

#include "ui_tft.h"
#include "ui_wifi_tft.h"
#include "ui_enroll_tft.h"
#include "ui_dashboard_tft.h"
#include "ui_settings_tft.h"

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
  SCREEN_DASHBOARD,
  SCREEN_SETTINGS
};

static AppScreen current_screen = SCREEN_NONE;

// WiFi watchdog
static uint32_t _last_wifi_check_ms = 0;
#define WIFI_CHECK_INTERVAL_MS 5000
#define WIFI_RECONNECT_TIMEOUT_MS 15000

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
static void _show_settings();
static void _show_wifi();
static void _on_settings_saved();

// Check if managers and permitopen rules are configured
static bool _rules_valid() {
  String managers = ui_load_string(NVS_KEY_MANAGERS);
  if (managers.length() == 0) {
    managers = ui_load_string(NVS_KEY_MANAGER);
  }
  String permitopen = ui_load_string(NVS_KEY_PERMITOPEN);

  if (managers.length() == 0) {
    Serial.println("[main] Rules invalid: no managers configured");
    return false;
  }
  if (permitopen.length() == 0) {
    Serial.println("[main] Rules invalid: no permitopen rules configured");
    return false;
  }
  return true;
}

// Parse a comma-separated string into an array of static String objects.
// Returns count of items parsed (up to max_items).
static int _parse_csv(const String &input, String *out, int max_items) {
  int count = 0;
  int start = 0;
  for (int i = 0; i <= (int)input.length() && count < max_items; i++) {
    if (i == (int)input.length() || input[i] == ',') {
      String item = input.substring(start, i);
      item.trim();
      if (item.length() > 0) {
        out[count++] = item;
      }
      start = i + 1;
    }
  }
  return count;
}

static bool start_daemon() {
  // These MUST be static — NoPortsDaemon::begin() stores pointers to them
  // via memcpy, so they must outlive the function call.
  // Re-assign on every call so NVS changes (settings save) take effect.
  static String atsign;
  static String device;
  static String managers_raw;
  static String manager_items[NOPORTS_MAX_MANAGERS];
  static String permitopen_raw;
  static String po_items[NOPORTS_MAX_PERMITOPEN];

  atsign  = ui_load_string(NVS_KEY_ATSIGN);
  device  = ui_load_string(NVS_KEY_DEVICE);

  // Load managers: prefer the new comma-separated key, fall back to single
  managers_raw = ui_load_string(NVS_KEY_MANAGERS);
  if (managers_raw.length() == 0) {
    managers_raw = ui_load_string(NVS_KEY_MANAGER);
  }
  int mgr_count = _parse_csv(managers_raw, manager_items, NOPORTS_MAX_MANAGERS);

  // Load permitopen rules
  permitopen_raw = ui_load_string(NVS_KEY_PERMITOPEN);
  int po_count = _parse_csv(permitopen_raw, po_items, NOPORTS_MAX_PERMITOPEN);

  if (atsign.length() == 0 || device.length() == 0) {
    Serial.println("[main] Missing atSign/device in NVS");
    return false;
  }

  NoPortsConfig config;
  noports_config_init(&config);
  config.atsign      = atsign.c_str();
  config.device_name = device.c_str();

  // Populate manager list
  for (int i = 0; i < mgr_count; i++) {
    config.manager_list[i] = manager_items[i].c_str();
  }
  config.manager_count = mgr_count;
  Serial.printf("[main] %d manager(s) configured\n", mgr_count);

  // Populate permitopen rules
  static String po_hosts[NOPORTS_MAX_PERMITOPEN]; // keep alive
  for (int i = 0; i < po_count; i++) {
    int colon = po_items[i].indexOf(':');
    if (colon > 0) {
      po_hosts[i] = po_items[i].substring(0, colon);
      config.permitopen[i].host = po_hosts[i].c_str();
      config.permitopen[i].port = (uint16_t)po_items[i].substring(colon + 1).toInt();
    } else if (po_items[i] == "*") {
      po_hosts[i] = "*";
      config.permitopen[i].host = "*";
      config.permitopen[i].port = 0;  // wildcard
    } else {
      po_hosts[i] = po_items[i];
      config.permitopen[i].host = po_hosts[i].c_str();
      config.permitopen[i].port = 0;
    }
  }
  config.permitopen_count = po_count;
  Serial.printf("[main] %d permitopen rule(s) configured\n", po_count);

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
    ui_dashboard_create(_do_reset, _show_settings, _show_wifi);
  } else {
    _show_daemon_error();
  }
}

static void on_wifi_connected() {
  TFT_eSPI &tft = ui_get_tft();

  // Show NTP sync status
  tft.fillRect(0, TFT_HEIGHT / 2 + 15, TFT_WIDTH, 20, COLOR_BG_DARK);
  tft.setTextColor(COLOR_ACCENT);
  tft.setTextDatum(MC_DATUM);
  tft.drawString("Syncing time...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);

  sync_ntp_time();
  
  if (ui_is_configured()) {
    // Check rules are valid before trying to start daemon
    if (!_rules_valid()) {
      Serial.println("[main] Rules missing — opening Rules screen");
      tft.fillRect(0, TFT_HEIGHT / 2 + 15, TFT_WIDTH, 20, COLOR_BG_DARK);
      tft.setTextColor(COLOR_ERROR);
      tft.setTextDatum(MC_DATUM);
      tft.drawString("Rules not configured!", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);
      delay(1500);
      current_screen = SCREEN_SETTINGS;
      ui_settings_create(_on_settings_saved);
      return;
    }

    // Show PKAM auth status
    tft.fillRect(0, TFT_HEIGHT / 2 + 15, TFT_WIDTH, 20, COLOR_BG_DARK);
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("Authenticating atSign...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);

    // Already enrolled – start daemon and go to dashboard
    if (start_daemon()) {
      current_screen = SCREEN_DASHBOARD;
      ui_dashboard_create(_do_reset, _show_settings, _show_wifi);
    } else {
      // Keys exist but auth failed – show error with reset option
      _show_daemon_error();
    }
  } else {
    // First run – show enrollment
    tft.fillRect(0, TFT_HEIGHT / 2 + 15, TFT_WIDTH, 20, COLOR_BG_DARK);
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("Starting enrollment...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);
    delay(500);

    current_screen = SCREEN_ENROLL;
    ui_enroll_create(_on_enrolled);
  }
}

// Called after WiFi reconnects from the WiFi screen (during runtime, not first boot)
// Helper: show a full-screen status message during daemon restart
static void _show_restart_status(const char *line1, const char *line2 = nullptr) {
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(1);
  tft.drawString("NoPorts CYD", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 40, 4);
  tft.setTextColor(COLOR_ACCENT);
  tft.drawString(line1, TFT_WIDTH / 2, TFT_HEIGHT / 2 + 5, 2);
  if (line2) {
    tft.setTextColor(COLOR_TEXT_GREY);
    tft.drawString(line2, TFT_WIDTH / 2, TFT_HEIGHT / 2 + 30, 2);
  }
}

static void _on_wifi_reconnected() {
  _show_restart_status("Syncing time...");
  sync_ntp_time();

  // Return to dashboard — daemon may need restart
  if (!daemon_running || !npDaemon.isRunning()) {
    _show_restart_status("Authenticating atSign...");

    bool started = false;
    for (int attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        char msg[40];
        snprintf(msg, sizeof(msg), "Retry %d/3...", attempt + 1);
        _show_restart_status("Authenticating atSign...", msg);
        Serial.printf("[main] Daemon start retry %d/3...\n", attempt + 1);
        delay(2000);
      }
      if (start_daemon()) { started = true; break; }
    }
    current_screen = SCREEN_DASHBOARD;
    ui_dashboard_create(_do_reset, _show_settings, _show_wifi);
    if (!started) {
      Serial.println("[main] WARNING: Daemon failed after WiFi reconnect");
    }
  } else {
    current_screen = SCREEN_DASHBOARD;
    ui_dashboard_create(_do_reset, _show_settings, _show_wifi);
  }
}

// Called when user saves settings screen
static void _on_settings_saved() {
  // Show status so user knows it's working, not frozen
  _show_restart_status("Saving rules...", "Restarting daemon");

  // Daemon restart needed to pick up new config
  if (daemon_running) {
    npDaemon.stop();
    daemon_running = false;
    Serial.println("[main] Daemon stopped for settings change");
  }

  _show_restart_status("Waiting for server...");
  delay(3000);

  // Log heap before restart attempt
  Serial.printf("[main] Free heap before daemon restart: %u bytes\n", ESP.getFreeHeap());

  // Retry daemon start (PKAM can fail transiently after quick restart)
  bool started = false;
  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      char msg[40];
      snprintf(msg, sizeof(msg), "Retry %d/3...", attempt + 1);
      _show_restart_status("Authenticating atSign...", msg);
      Serial.printf("[main] Daemon start retry %d/3...\n", attempt + 1);
      delay(3000);
    } else {
      _show_restart_status("Authenticating atSign...");
    }
    if (start_daemon()) { started = true; break; }
  }

  current_screen = SCREEN_DASHBOARD;
  ui_dashboard_create(_do_reset, _show_settings, _show_wifi);
  if (!started) {
    Serial.println("[main] WARNING: Daemon failed to restart after settings save");
  }
}

// Show settings/rules screen (called from dashboard)
static void _show_settings() {
  current_screen = SCREEN_SETTINGS;
  ui_settings_create(_on_settings_saved);
}

// Show WiFi setup screen (called from dashboard)
static void _show_wifi() {
  if (daemon_running) {
    npDaemon.stop();
    daemon_running = false;
  }
  current_screen = SCREEN_WIFI;
  ui_wifi_create(_on_wifi_reconnected);
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
    // ---------------------------------------------------------------
    // Boot WiFi screen: 5-second countdown with "Change WiFi" button.
    // WiFi connection starts immediately but the countdown always runs
    // the full 5 seconds so the user has time to press "Change WiFi".
    // ---------------------------------------------------------------
    TFT_eSPI &tft = ui_get_tft();
    tft.fillScreen(COLOR_BG_DARK);

    // Title
    tft.setTextColor(COLOR_PRIMARY);
    tft.setTextDatum(TC_DATUM);
    tft.setTextSize(1);
    tft.drawString("NoPorts CYD", TFT_WIDTH / 2, 20, 4);

    // SSID
    tft.setTextColor(COLOR_TEXT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(ssid.c_str(), TFT_WIDTH / 2, TFT_HEIGHT / 2 - 30, 2);

    // "Change WiFi" button
    const int btn_x = TFT_WIDTH / 2 - 60;
    const int btn_y = TFT_HEIGHT / 2 + 40;
    const int btn_w = 120;
    const int btn_h = 30;
    ui_draw_rounded_rect(btn_x, btn_y, btn_w, btn_h, 6, COLOR_ACCENT);
    tft.setTextColor(COLOR_TEXT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("Change WiFi", btn_x + btn_w / 2, btn_y + btn_h / 2, 2);

    // Hint text below button
    tft.setTextColor(COLOR_TEXT_GREY);
    tft.setTextDatum(TC_DATUM);
    tft.drawString("Tap button to reconfigure", TFT_WIDTH / 2, btn_y + btn_h + 6, 1);

    // Progress bar outline
    const int bar_x = 30;
    const int bar_y = TFT_HEIGHT / 2;
    const int bar_w = TFT_WIDTH - 60;
    const int bar_h = 14;
    tft.drawRect(bar_x, bar_y, bar_w, bar_h, COLOR_TEXT_GREY);

    // Start WiFi connection attempt in background
    WiFi.mode(WIFI_STA);
    String pass = ui_load_string(NVS_KEY_PASS);
    WiFi.begin(ssid.c_str(), pass.c_str());

    const unsigned long COUNTDOWN_MS = 5000;
    unsigned long boot_wifi_start = millis();
    bool user_aborted = false;
    bool wifi_connected = false;
    int prev_fill_w = 0;
    const char *prev_status = "";

    // Always run the full 5-second countdown so user can press "Change WiFi"
    while (millis() - boot_wifi_start < COUNTDOWN_MS) {
      // Check for touch on "Change WiFi" button
      int16_t tx, ty;
      if (ui_touch_read(&tx, &ty)) {
        if (ui_touch_in_rect(tx, ty, btn_x, btn_y, btn_w, btn_h)) {
          user_aborted = true;
          Serial.println("[main] User pressed Change WiFi");
          WiFi.disconnect();
          break;
        }
        // Ignore taps elsewhere — don't abort
      }

      // Track WiFi status (don't break — keep counting down)
      if (!wifi_connected && WiFi.status() == WL_CONNECTED) {
        wifi_connected = true;
        Serial.println("[main] WiFi connected during countdown");
      }

      // Update countdown bar (incremental fill only — no flicker)
      unsigned long elapsed = millis() - boot_wifi_start;
      int fill_w = (int)((unsigned long)(bar_w - 2) * elapsed / COUNTDOWN_MS);
      if (fill_w > prev_fill_w && fill_w <= bar_w - 2) {
        uint16_t bar_color = wifi_connected ? COLOR_SUCCESS : COLOR_ACCENT;
        tft.fillRect(bar_x + 1 + prev_fill_w, bar_y + 1,
                     fill_w - prev_fill_w, bar_h - 2, bar_color);
        prev_fill_w = fill_w;
      }

      // Status text (only redraw when it changes)
      const char *status;
      int secs_left = (int)((COUNTDOWN_MS - elapsed + 999) / 1000);
      char countdown_buf[48];
      if (wifi_connected) {
        snprintf(countdown_buf, sizeof(countdown_buf), "WiFi OK! Starting in %ds...", secs_left);
        status = countdown_buf;
      } else {
        snprintf(countdown_buf, sizeof(countdown_buf), "Connecting WiFi... %ds", secs_left);
        status = countdown_buf;
      }
      // Always redraw status (secs_left changes)
      tft.fillRect(0, TFT_HEIGHT / 2 - 15, TFT_WIDTH, 14, COLOR_BG_DARK);
      tft.setTextColor(wifi_connected ? COLOR_SUCCESS : COLOR_ACCENT);
      tft.setTextDatum(MC_DATUM);
      tft.drawString(countdown_buf, TFT_WIDTH / 2, TFT_HEIGHT / 2 - 8, 2);

      delay(50);
    }

    if (user_aborted) {
      // User wants to change WiFi
      Serial.println("[main] Showing WiFi setup (user request)");
      current_screen = SCREEN_WIFI;
      ui_wifi_create(on_wifi_connected);
    } else if (wifi_connected || WiFi.status() == WL_CONNECTED) {
      Serial.println("[main] Auto-connected to WiFi");
      ui_set_led(false, false, true);  // Blue = connected

      // Show status while NTP + daemon start (these can take several seconds)
      tft.fillScreen(COLOR_BG_DARK);
      tft.setTextColor(COLOR_PRIMARY);
      tft.setTextDatum(MC_DATUM);
      tft.setTextSize(1);
      tft.drawString("NoPorts CYD", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 40, 4);
      tft.setTextColor(COLOR_TEXT_WHITE);
      tft.drawString(WiFi.localIP().toString().c_str(), TFT_WIDTH / 2, TFT_HEIGHT / 2 - 5, 2);
      tft.setTextColor(COLOR_ACCENT);
      tft.drawString("Syncing time...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);

      on_wifi_connected();
    } else {
      // Countdown expired without connection — try a few more seconds
      Serial.println("[main] Countdown expired, waiting 5s more...");
      tft.fillRect(0, TFT_HEIGHT / 2 - 15, TFT_WIDTH, 14, COLOR_BG_DARK);
      tft.setTextColor(COLOR_ERROR);
      tft.setTextDatum(MC_DATUM);
      tft.drawString("Still connecting...", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 8, 2);

      unsigned long extra_start = millis();
      while (WiFi.status() != WL_CONNECTED && millis() - extra_start < 5000) {
        delay(100);
      }
      if (WiFi.status() == WL_CONNECTED) {
        Serial.println("[main] Connected (late)");
        ui_set_led(false, false, true);

        tft.fillScreen(COLOR_BG_DARK);
        tft.setTextColor(COLOR_PRIMARY);
        tft.setTextDatum(MC_DATUM);
        tft.setTextSize(1);
        tft.drawString("NoPorts CYD", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 40, 4);
        tft.setTextColor(COLOR_TEXT_WHITE);
        tft.drawString(WiFi.localIP().toString().c_str(), TFT_WIDTH / 2, TFT_HEIGHT / 2 - 5, 2);
        tft.setTextColor(COLOR_ACCENT);
        tft.drawString("Syncing time...", TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);

        on_wifi_connected();
      } else {
        Serial.println("[main] Auto-connect failed - showing WiFi setup");
        WiFi.disconnect();
        current_screen = SCREEN_WIFI;
        ui_wifi_create(on_wifi_connected);
      }
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
  // -----------------------------------------------------------------------
  // WiFi disconnect watchdog (only when we expect WiFi to be up)
  // -----------------------------------------------------------------------
  if (current_screen == SCREEN_DASHBOARD && millis() - _last_wifi_check_ms > WIFI_CHECK_INTERVAL_MS) {
    _last_wifi_check_ms = millis();
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("[main] WiFi disconnected — attempting reconnect...");
      ui_set_led(true, false, false);  // Red = disconnected

      // Try quick reconnect with saved credentials
      if (!ui_wifi_auto_connect(WIFI_RECONNECT_TIMEOUT_MS)) {
        Serial.println("[main] Reconnect failed — showing WiFi setup");
        if (daemon_running) {
          npDaemon.stop();
          daemon_running = false;
        }
        current_screen = SCREEN_WIFI;
        ui_wifi_create(_on_wifi_reconnected);
        return;  // skip rest of this loop iteration
      }
      Serial.println("[main] WiFi reconnected");
      ui_load_led_color();  // restore LED
    }
  }

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
        
      case SCREEN_SETTINGS:
        ui_settings_handle_touch(tx, ty);
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
      
    case SCREEN_SETTINGS:
      ui_settings_update();
      break;
      
    case SCREEN_DASHBOARD:
      // Drive NoPorts daemon
      if (daemon_running && npDaemon.isRunning()) {
        npDaemon.loop();
        
        // Update dashboard periodically
        static uint32_t last_update = 0;
        if (millis() - last_update > 500) {
          last_update = millis();
          uint32_t tp_in = 0, tp_out = 0;
          npDaemon.getThroughput(tp_in, tp_out);
          ui_dashboard_update(npDaemon.getActiveRelayCount(),
                            daemon_state_str(npDaemon.getState()),
                            _total_tunnels, _total_pings,
                            tp_in, tp_out);
        }
      }
      break;
      
    default:
      break;
  }
  
  delay(10);  // Reduced from 5ms to save CPU
}
