/**
 * @file ui_wifi_tft.cpp
 * @brief WiFi setup screen implementation using TFT_eSPI
 */

#include "ui_wifi_tft.h"
#include "ui_tft.h"
#include <WiFi.h>
#include <Arduino.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define MAX_NETWORKS     8
#define NETWORK_HEIGHT   28
#define LIST_START_Y     50
#define KEYBOARD_HEIGHT  130

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
enum WifiState {
  WIFI_SCANNING,
  WIFI_SHOW_LIST,
  WIFI_ENTER_PASSWORD,
  WIFI_CONNECTING,
  WIFI_CONNECTED,
  WIFI_ERROR
};

static WifiState _state = WIFI_SCANNING;
static String _networks[MAX_NETWORKS];
static int _network_count = 0;
static int _selected_network = -1;
static char _password[64] = "";
static int _password_len = 0;
static void (*_on_connected_cb)() = nullptr;
static uint32_t _scan_start_ms = 0;
static uint32_t _connect_start_ms = 0;
static String _status_msg;

// Simple on-screen keyboard keys
static const char* _keyboard_keys[] = {
  "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
  "q", "w", "e", "r", "t", "y", "u", "i", "o", "p",
  "a", "s", "d", "f", "g", "h", "j", "k", "l", "-",
  "z", "x", "c", "v", "b", "n", "m", "_", ".", "!",
  "DEL", "SPACE", "OK"
};
static const int _keyboard_key_count = sizeof(_keyboard_keys) / sizeof(_keyboard_keys[0]);

#define KEYS_PER_ROW 10
#define KEY_WIDTH    30
#define KEY_HEIGHT   18
#define KEY_SPACING  1

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static void _draw_keyboard();
static bool _check_keyboard_press(int16_t tx, int16_t ty);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void _draw_header(const char *title) {
  TFT_eSPI &tft = ui_get_tft();
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(TC_DATUM);
  tft.setTextSize(1);
  tft.drawString(title, TFT_WIDTH / 2, 10, 4);
}

static void _draw_status(const char *msg) {
  TFT_eSPI &tft = ui_get_tft();
  
  // Clear status area
  tft.fillRect(0, 30, TFT_WIDTH, 16, COLOR_BG_DARK);
  
  // Draw message
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextDatum(TC_DATUM);
  tft.setTextSize(1);
  tft.drawString(msg, TFT_WIDTH / 2, 30, 2);
}

static void _start_scan() {
  _state = WIFI_SCANNING;
  _network_count = 0;
  _scan_start_ms = millis();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  WiFi.scanNetworks(true);  // Async scan
  Serial.println("[ui_wifi] Starting WiFi scan...");
}

static void _draw_network_list() {
  TFT_eSPI &tft = ui_get_tft();
  
  // Clear list area
  tft.fillRect(0, LIST_START_Y, TFT_WIDTH, TFT_HEIGHT - LIST_START_Y, COLOR_BG_DARK);
  
  int y = LIST_START_Y;
  for (int i = 0; i < _network_count && i < MAX_NETWORKS; i++) {
    // Highlight selected network
    uint16_t bg_color = (i == _selected_network) ? COLOR_BG_CARD : COLOR_BG_DARK;
    tft.fillRoundRect(5, y, TFT_WIDTH - 10, NETWORK_HEIGHT - 4, 4, bg_color);
    
    // Draw SSID and signal strength
    tft.setTextColor(COLOR_TEXT_WHITE);
    tft.setTextDatum(ML_DATUM);
    tft.setTextSize(1);
    tft.drawString(_networks[i].c_str(), 10, y + NETWORK_HEIGHT / 2, 2);
    
    y += NETWORK_HEIGHT;
  }
}

static void _draw_password_entry() {
  TFT_eSPI &tft = ui_get_tft();
  
  // Draw selected SSID at top
  tft.fillRect(0, LIST_START_Y, TFT_WIDTH, 30, COLOR_BG_DARK);
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(TC_DATUM);
  tft.setTextSize(1);
  tft.drawString(_networks[_selected_network].c_str(), TFT_WIDTH / 2, LIST_START_Y + 5, 2);
  
  // Draw password field
  int field_y = LIST_START_Y + 35;
  ui_draw_rounded_rect(10, field_y, TFT_WIDTH - 20, 30, 4, COLOR_BG_CARD);
  
  // Show password (masked)
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(ML_DATUM);
  String masked(_password_len, '*');
  tft.drawString(masked.c_str(), 15, field_y + 15, 2);
  
  // Draw keyboard
  _draw_keyboard();
}

static void _draw_keyboard() {
  TFT_eSPI &tft = ui_get_tft();
  
  int kb_start_y = TFT_HEIGHT - KEYBOARD_HEIGHT;
  tft.fillRect(0, kb_start_y, TFT_WIDTH, KEYBOARD_HEIGHT, COLOR_BG_DARK);
  
  int key_idx = 0;
  int row = 0;
  int x_start = 5;
  
  for (int i = 0; i < _keyboard_key_count; i++) {
    int col = key_idx % KEYS_PER_ROW;
    int x = x_start + col * (KEY_WIDTH + KEY_SPACING);
    int y = kb_start_y + row * (KEY_HEIGHT + KEY_SPACING) + 2;
    
    // Wide keys: DEL=3cols, SPACE=4cols, OK=3cols (total 10 = full row)
    int key_w = KEY_WIDTH;
    int col_span = 1;
    if (strcmp(_keyboard_keys[i], "DEL") == 0) {
      key_w = KEY_WIDTH * 3 + KEY_SPACING * 2;
      col_span = 3;
    } else if (strcmp(_keyboard_keys[i], "SPACE") == 0) {
      key_w = KEY_WIDTH * 4 + KEY_SPACING * 3;
      col_span = 4;
    } else if (strcmp(_keyboard_keys[i], "OK") == 0) {
      key_w = KEY_WIDTH * 3 + KEY_SPACING * 2;
      col_span = 3;
    }
    
    // Draw key
    ui_draw_rounded_rect(x, y, key_w, KEY_HEIGHT, 3, COLOR_BUTTON_BG);
    
    tft.setTextColor(COLOR_TEXT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.setTextSize(1);
    tft.drawString(_keyboard_keys[i], x + key_w / 2, y + KEY_HEIGHT / 2, 2);
    
    key_idx += col_span;
    if (key_idx >= KEYS_PER_ROW) {
      row++;
      key_idx = 0;
    }
  }
}

static bool _check_keyboard_press(int16_t tx, int16_t ty) {
  int kb_start_y = TFT_HEIGHT - KEYBOARD_HEIGHT;
  int key_idx = 0;
  int row = 0;
  int x_start = 5;
  
  for (int i = 0; i < _keyboard_key_count; i++) {
    int col = key_idx % KEYS_PER_ROW;
    int x = x_start + col * (KEY_WIDTH + KEY_SPACING);
    int y = kb_start_y + row * (KEY_HEIGHT + KEY_SPACING) + 2;
    
    // Wide keys: DEL=3cols, SPACE=4cols, OK=3cols
    int key_w = KEY_WIDTH;
    int col_span = 1;
    if (strcmp(_keyboard_keys[i], "DEL") == 0) {
      key_w = KEY_WIDTH * 3 + KEY_SPACING * 2;
      col_span = 3;
    } else if (strcmp(_keyboard_keys[i], "SPACE") == 0) {
      key_w = KEY_WIDTH * 4 + KEY_SPACING * 3;
      col_span = 4;
    } else if (strcmp(_keyboard_keys[i], "OK") == 0) {
      key_w = KEY_WIDTH * 3 + KEY_SPACING * 2;
      col_span = 3;
    }
    
    if (ui_touch_in_rect(tx, ty, x, y, key_w, KEY_HEIGHT)) {
      // Handle key press
      if (strcmp(_keyboard_keys[i], "DEL") == 0) {
        if (_password_len > 0) {
          _password[--_password_len] = '\0';
        }
      } else if (strcmp(_keyboard_keys[i], "SPACE") == 0) {
        if (_password_len < 63) {
          _password[_password_len++] = ' ';
          _password[_password_len] = '\0';
        }
      } else if (strcmp(_keyboard_keys[i], "OK") == 0) {
        // Start connection
        _state = WIFI_CONNECTING;
        _connect_start_ms = millis();
        WiFi.begin(_networks[_selected_network].c_str(), _password);
        Serial.printf("[ui_wifi] Connecting to %s...\n", _networks[_selected_network].c_str());
      } else {
        // Regular character
        if (_password_len < 63) {
          _password[_password_len++] = _keyboard_keys[i][0];
          _password[_password_len] = '\0';
        }
      }
      
      _draw_password_entry();
      return true;
    }
    
    key_idx += col_span;
    if (key_idx >= KEYS_PER_ROW) {
      row++;
      key_idx = 0;
    }
  }
  
  return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void ui_wifi_create(void (*on_connected)()) {
  _on_connected_cb = on_connected;
  
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  
  _draw_header("WiFi Setup");
  _start_scan();
}

void ui_wifi_update() {
  switch (_state) {
    case WIFI_SCANNING: {
      // Check if scan is complete
      int n = WiFi.scanComplete();
      if (n == WIFI_SCAN_FAILED) {
        _status_msg = "Scan failed";
        _draw_status(_status_msg.c_str());
        delay(2000);
        _start_scan();
      } else if (n >= 0) {
        // Scan complete
        _network_count = min(n, MAX_NETWORKS);
        for (int i = 0; i < _network_count; i++) {
          _networks[i] = WiFi.SSID(i);
        }
        Serial.printf("[ui_wifi] Found %d networks\n", _network_count);
        _state = WIFI_SHOW_LIST;
        _draw_status("Touch to select network");
        _draw_network_list();
        WiFi.scanDelete();
      } else {
        // Still scanning
        if (millis() - _scan_start_ms > 10000) {
          _status_msg = "Scan timeout";
          _draw_status(_status_msg.c_str());
          delay(2000);
          _start_scan();
        } else {
          _draw_status("Scanning...");
        }
      }
      break;
    }
    
    case WIFI_CONNECTING: {
      // Check connection status
      if (WiFi.status() == WL_CONNECTED) {
        _state = WIFI_CONNECTED;
        
        // Save credentials
        ui_save_string(NVS_KEY_SSID, _networks[_selected_network].c_str());
        ui_save_string(NVS_KEY_PASS, _password);
        
        Serial.printf("[ui_wifi] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
        
        TFT_eSPI &tft = ui_get_tft();
        tft.fillScreen(COLOR_BG_DARK);
        tft.setTextColor(COLOR_SUCCESS);
        tft.setTextDatum(MC_DATUM);
        tft.setTextSize(1);
        tft.drawString("Connected!", TFT_WIDTH / 2, TFT_HEIGHT / 2 - 20, 4);
        tft.setTextColor(COLOR_TEXT_WHITE);
        tft.drawString(WiFi.localIP().toString().c_str(), TFT_WIDTH / 2, TFT_HEIGHT / 2 + 20, 2);
        
        delay(2000);
        
        if (_on_connected_cb) {
          _on_connected_cb();
        }
      } else if (millis() - _connect_start_ms > 15000) {
        // Timeout
        _state = WIFI_ERROR;
        TFT_eSPI &tft = ui_get_tft();
        tft.fillScreen(COLOR_BG_DARK);
        tft.setTextColor(COLOR_ERROR);
        tft.setTextDatum(MC_DATUM);
        tft.setTextSize(1);
        tft.drawString("Connection Failed", TFT_WIDTH / 2, TFT_HEIGHT / 2, 4);
        delay(2000);
        
        // Return to list
        _state = WIFI_SHOW_LIST;
        _selected_network = -1;
        _password_len = 0;
        _password[0] = '\0';
        
        TFT_eSPI &tft2 = ui_get_tft();
        tft2.fillScreen(COLOR_BG_DARK);
        _draw_header("WiFi Setup");
        _draw_status("Touch to select network");
        _draw_network_list();
      } else {
        // Still connecting
        _draw_status("Connecting...");
      }
      break;
    }
    
    default:
      break;
  }
}

bool ui_wifi_handle_touch(int16_t tx, int16_t ty) {
  if (_state == WIFI_SHOW_LIST) {
    // Check if a network was tapped
    int y = LIST_START_Y;
    for (int i = 0; i < _network_count && i < MAX_NETWORKS; i++) {
      if (ui_touch_in_rect(tx, ty, 5, y, TFT_WIDTH - 10, NETWORK_HEIGHT - 4)) {
        _selected_network = i;
        _password_len = 0;
        _password[0] = '\0';
        _state = WIFI_ENTER_PASSWORD;
        
        TFT_eSPI &tft = ui_get_tft();
        tft.fillScreen(COLOR_BG_DARK);
        _draw_header("Enter Password");
        _draw_password_entry();
        
        Serial.printf("[ui_wifi] Selected: %s\n", _networks[i].c_str());
        return true;
      }
      y += NETWORK_HEIGHT;
    }
  } else if (_state == WIFI_ENTER_PASSWORD) {
    return _check_keyboard_press(tx, ty);
  }
  
  return false;
}

bool ui_wifi_auto_connect(int timeout_ms) {
  String ssid = ui_load_string(NVS_KEY_SSID);
  String pass = ui_load_string(NVS_KEY_PASS);
  
  if (ssid.length() == 0) {
    Serial.println("[ui_wifi] No saved credentials");
    return false;
  }
  
  Serial.printf("[ui_wifi] Auto-connecting to: %s\n", ssid.c_str());
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());
  
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - start > timeout_ms) {
      Serial.println("[ui_wifi] Auto-connect timeout");
      WiFi.disconnect();
      return false;
    }
    delay(100);
  }
  
  Serial.printf("[ui_wifi] Auto-connected! IP: %s\n", WiFi.localIP().toString().c_str());
  return true;
}

String ui_wifi_get_ip() {
  if (WiFi.status() == WL_CONNECTED) {
    return WiFi.localIP().toString();
  }
  return "0.0.0.0";
}
