/**
 * @file ui_dashboard_tft.cpp
 * @brief Dashboard screen implementation using TFT_eSPI
 */

#include "ui_dashboard_tft.h"
#include "ui_tft.h"
#include <Arduino.h>
#include <WiFi.h>

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------
#define HEADER_HEIGHT     30
#define HEADER_PADDING    3
#define STATS_ROW1_Y      (HEADER_PADDING + HEADER_HEIGHT + 3)
#define STATS_ROW2_Y      (STATS_ROW1_Y + 26)
#define LOG_TOP_Y         (STATS_ROW2_Y + 26)
#define LOG_HEIGHT        48
#define GRAPH_TOP_Y       (LOG_TOP_Y + LOG_HEIGHT + 3)
#define GRAPH_HEIGHT      54
#define BOTTOM_ROW_Y      (TFT_HEIGHT - 30)
#define SPACING           3

#define LOG_MAX_ENTRIES   3
#define LOG_ENTRY_HEIGHT  14

// Throughput graph
#define GRAPH_SAMPLES     40
#define GRAPH_PAD_L       38   // left padding for axis labels
#define GRAPH_PAD_R       4
#define GRAPH_PAD_T       12   // top padding for title
#define GRAPH_PAD_B       2

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static uint32_t _boot_ms = 0;
static int _active_relays = 0;
static uint32_t _total_tunnels = 0;
static uint32_t _total_pings = 0;
static char _daemon_state[32] = "init";
static void (*_on_reset_cb)() = nullptr;

// Log entries (ring buffer)
struct LogEntry {
  char text[EVENT_TEXT_LEN];
  uint16_t color;
  bool used;
};

static LogEntry _log_entries[LOG_MAX_ENTRIES];
static int _log_head = 0;

// Throughput graph ring buffer
static uint32_t _tp_in[GRAPH_SAMPLES];   // bytes received per sample period
static uint32_t _tp_out[GRAPH_SAMPLES];  // bytes sent per sample period
static int _tp_head = 0;
static uint32_t _prev_bytes_in = 0;
static uint32_t _prev_bytes_out = 0;

// LED color presets
struct LedPreset {
  const char *label;
  bool r, g, b;
  uint16_t hex;
  int16_t x, y;
};

static LedPreset _led_presets[] = {
  {"Off",   false, false, false, 0x4208, 0, 0},
  {"Grn",   false, true,  false, 0x07E0, 0, 0},
  {"Blu",   false, false, true,  0x001F, 0, 0},
  {"Cyan",  false, true,  true,  0x07FF, 0, 0},
  {"Wht",   true,  true,  true,  0xFFFF, 0, 0},
};
static const int _led_preset_count = sizeof(_led_presets) / sizeof(_led_presets[0]);

// WiFi / identity info
static String _atsign;
static String _device;

// Reset button area
static const int RESET_BTN_X = TFT_WIDTH - 55;
static const int RESET_BTN_Y = BOTTOM_ROW_Y;
static const int RESET_BTN_W = 50;
static const int RESET_BTN_H = 24;

// Confirm-reset state
static bool _reset_confirming = false;
static uint32_t _reset_confirm_ms = 0;
#define RESET_CONFIRM_TIMEOUT 3000  // 3 seconds to confirm

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void _add_log_entry(const char *text, uint16_t color) {
  LogEntry &entry = _log_entries[_log_head];
  strncpy(entry.text, text, EVENT_TEXT_LEN - 1);
  entry.text[EVENT_TEXT_LEN - 1] = '\0';
  entry.color = color;
  entry.used = true;
  _log_head = (_log_head + 1) % LOG_MAX_ENTRIES;
}

static void _draw_header() {
  TFT_eSPI &tft = ui_get_tft();
  int y = HEADER_PADDING;
  
  // Background card
  ui_draw_rounded_rect(HEADER_PADDING, y, TFT_WIDTH - 6, HEADER_HEIGHT, 5, COLOR_BG_CARD);
  
  // atSign (left)
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString(_atsign.c_str(), HEADER_PADDING + 6, y + HEADER_HEIGHT / 2, 2);
  
  // Device name (center)
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(_device.c_str(), TFT_WIDTH / 2, y + HEADER_HEIGHT / 2, 2);
  
  // IP address (right)
  String ip = WiFi.localIP().toString();
  tft.setTextColor(COLOR_ACCENT);
  tft.setTextDatum(MR_DATUM);
  tft.drawString(ip.c_str(), TFT_WIDTH - HEADER_PADDING - 6, y + HEADER_HEIGHT / 2, 2);
}

static void _draw_stats_row1() {
  TFT_eSPI &tft = ui_get_tft();
  int y = STATS_ROW1_Y;
  
  // Background card
  ui_draw_rounded_rect(HEADER_PADDING, y, TFT_WIDTH - 6, 22, 4, COLOR_BG_CARD);
  
  char buf[40];
  
  // State indicator (colored dot + text)
  uint16_t state_color = COLOR_TEXT_GREY;
  if (strcmp(_daemon_state, "running") == 0) state_color = COLOR_SUCCESS;
  else if (strcmp(_daemon_state, "auth") == 0) state_color = COLOR_ACCENT;
  else if (strcmp(_daemon_state, "error") == 0) state_color = COLOR_ERROR;
  
  tft.fillCircle(HEADER_PADDING + 12, y + 11, 4, state_color);
  
  snprintf(buf, sizeof(buf), "%s", _daemon_state);
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString(buf, HEADER_PADDING + 22, y + 11, 2);
  
  // Active relays (center)
  snprintf(buf, sizeof(buf), "Active: %d", _active_relays);
  tft.setTextColor(_active_relays > 0 ? COLOR_SUCCESS : COLOR_TEXT_GREY);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(buf, TFT_WIDTH / 2, y + 11, 2);
  
  // Uptime (right)
  char uptime_str[20];
  ui_format_uptime(millis() - _boot_ms, uptime_str, sizeof(uptime_str));
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextDatum(MR_DATUM);
  tft.drawString(uptime_str, TFT_WIDTH - HEADER_PADDING - 6, y + 11, 2);
}

static void _draw_stats_row2() {
  TFT_eSPI &tft = ui_get_tft();
  int y = STATS_ROW2_Y;
  
  // Background card
  ui_draw_rounded_rect(HEADER_PADDING, y, TFT_WIDTH - 6, 22, 4, COLOR_BG_CARD);
  
  char buf[40];
  
  // Total tunnels (left)
  snprintf(buf, sizeof(buf), "Tunnels: %lu", (unsigned long)_total_tunnels);
  tft.setTextColor(COLOR_ACCENT);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString(buf, HEADER_PADDING + 8, y + 11, 2);
  
  // Total pings (center)
  snprintf(buf, sizeof(buf), "Pings: %lu", (unsigned long)_total_pings);
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(buf, TFT_WIDTH / 2, y + 11, 2);
  
  // Free heap (right)
  snprintf(buf, sizeof(buf), "Heap: %uK", ESP.getFreeHeap() / 1024);
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextDatum(MR_DATUM);
  tft.drawString(buf, TFT_WIDTH - HEADER_PADDING - 6, y + 11, 2);
}

static void _draw_log() {
  TFT_eSPI &tft = ui_get_tft();
  int y = LOG_TOP_Y;
  
  // Background card
  ui_draw_rounded_rect(HEADER_PADDING, y, TFT_WIDTH - 6, LOG_HEIGHT, 5, COLOR_BG_CARD);
  
  // Draw log entries (most recent first)
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);
  
  int entry_y = y + 4;
  int displayed = 0;
  
  for (int i = 0; i < LOG_MAX_ENTRIES && displayed < LOG_MAX_ENTRIES; i++) {
    int idx = (_log_head - 1 - i + LOG_MAX_ENTRIES) % LOG_MAX_ENTRIES;
    
    if (_log_entries[idx].used) {
      tft.setTextColor(_log_entries[idx].color);
      tft.drawString(_log_entries[idx].text, HEADER_PADDING + 8, entry_y, 2);
      entry_y += LOG_ENTRY_HEIGHT;
      displayed++;
      
      if (entry_y + LOG_ENTRY_HEIGHT > y + LOG_HEIGHT) break;
    }
  }
}

static void _format_bytes(uint32_t bytes, char *buf, size_t len) {
  if (bytes >= 1048576)
    snprintf(buf, len, "%.1fM", bytes / 1048576.0f);
  else if (bytes >= 1024)
    snprintf(buf, len, "%.1fK", bytes / 1024.0f);
  else
    snprintf(buf, len, "%luB", (unsigned long)bytes);
}

static void _draw_graph() {
  TFT_eSPI &tft = ui_get_tft();
  int x0 = HEADER_PADDING;
  int y0 = GRAPH_TOP_Y;
  int w  = TFT_WIDTH - 6;
  int h  = GRAPH_HEIGHT;

  // Background card
  ui_draw_rounded_rect(x0, y0, w, h, 5, COLOR_BG_CARD);

  // Graph plotting area (inside card, below title)
  int gx = x0 + GRAPH_PAD_L;
  int gy = y0 + GRAPH_PAD_T;
  int gw = w - GRAPH_PAD_L - GRAPH_PAD_R;
  int gh = h - GRAPH_PAD_T - GRAPH_PAD_B;

  if (gw <= 0 || gh <= 0) return;

  // Explicitly clear the plotting area so stale bars are wiped
  tft.fillRect(gx, gy, gw, gh, COLOR_BG_CARD);

  // Also clear the label column so old axis text is wiped
  tft.fillRect(x0 + 1, gy, GRAPH_PAD_L - 1, gh, COLOR_BG_CARD);

  // Find max value for scaling
  uint32_t max_val = 1;  // avoid /0
  for (int i = 0; i < GRAPH_SAMPLES; i++) {
    uint32_t combined = _tp_in[i] + _tp_out[i];
    if (combined > max_val) max_val = combined;
  }

  // Current rate text (top-right, drawn first so bars don't obscure)
  int last_idx = (_tp_head - 1 + GRAPH_SAMPLES) % GRAPH_SAMPLES;
  char tot_in[12], tot_out[12];
  _format_bytes(_tp_in[last_idx] * 2, tot_in, sizeof(tot_in));   // *2 for per-second (500ms sample)
  _format_bytes(_tp_out[last_idx] * 2, tot_out, sizeof(tot_out));

  char rate_str[32];
  snprintf(rate_str, sizeof(rate_str), "in:%s/s out:%s/s", tot_in, tot_out);
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(TR_DATUM);
  tft.setTextSize(1);
  tft.drawString(rate_str, x0 + w - 6, y0 + 2, 1);

  // Title (top-left)
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextDatum(TL_DATUM);
  tft.drawString("Throughput", x0 + 6, y0 + 2, 1);

  // Y-axis labels (top = max, bottom = 0)
  char label[12];
  _format_bytes(max_val, label, sizeof(label));
  tft.setTextColor(COLOR_TEXT_GREY);
  tft.setTextDatum(MR_DATUM);
  tft.drawString(label, gx - 3, gy + 4, 1);
  tft.drawString("0", gx - 3, gy + gh - 2, 1);

  // Draw stacked bars (in = teal, out = orange)
  int bar_w = gw / GRAPH_SAMPLES;
  if (bar_w < 1) bar_w = 1;
  int bar_gap = (bar_w > 2) ? 1 : 0;

  for (int i = 0; i < GRAPH_SAMPLES; i++) {
    int idx = (_tp_head + i) % GRAPH_SAMPLES;
    uint32_t val_in  = _tp_in[idx];
    uint32_t val_out = _tp_out[idx];
    if (val_in == 0 && val_out == 0) continue;  // skip empty bars

    int bx = gx + i * bar_w;
    if (bx + bar_w > gx + gw) break;  // don't draw past right edge

    // Use uint64_t to prevent overflow on large throughput values
    int h_in  = (int)((uint64_t)val_in  * gh / max_val);
    int h_out = (int)((uint64_t)val_out * gh / max_val);

    // Clamp each individually, then combined
    if (h_in  > gh) h_in  = gh;
    if (h_out > gh) h_out = gh;
    if (h_in + h_out > gh) h_out = gh - h_in;
    if (h_in  < 0) h_in  = 0;
    if (h_out < 0) h_out = 0;

    // Draw "in" bar (teal) from bottom
    if (h_in > 0) {
      tft.fillRect(bx, gy + gh - h_in, bar_w - bar_gap, h_in, COLOR_ACCENT);
    }
    // Draw "out" bar (orange) stacked above
    if (h_out > 0) {
      tft.fillRect(bx, gy + gh - h_in - h_out, bar_w - bar_gap, h_out, COLOR_PRIMARY);
    }
  }
}

static void _draw_bottom_row() {
  TFT_eSPI &tft = ui_get_tft();
  int y = BOTTOM_ROW_Y;
  
  // LED color buttons (left side)
  const int btn_width = 42;
  const int btn_height = 24;
  int x = HEADER_PADDING;
  
  for (int i = 0; i < _led_preset_count; i++) {
    _led_presets[i].x = x;
    _led_presets[i].y = y;
    
    ui_draw_rounded_rect(x, y, btn_width, btn_height, 4, _led_presets[i].hex);
    
    bool bright = _led_presets[i].hex > 0x7BEF;
    tft.setTextColor(bright ? 0x0000 : COLOR_TEXT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.setTextSize(1);
    tft.drawString(_led_presets[i].label, x + btn_width / 2, y + btn_height / 2, 2);
    
    x += btn_width + 2;
  }
  
  // Reset button (right side, red)
  uint16_t reset_color = _reset_confirming ? COLOR_ERROR : 0x8000;  // bright red if confirming
  ui_draw_rounded_rect(RESET_BTN_X, RESET_BTN_Y, RESET_BTN_W, RESET_BTN_H, 4, reset_color);
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(_reset_confirming ? "Sure?" : "Reset",
                 RESET_BTN_X + RESET_BTN_W / 2, RESET_BTN_Y + RESET_BTN_H / 2, 2);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void ui_dashboard_create(void (*on_reset)()) {
  _boot_ms = millis();
  _on_reset_cb = on_reset;
  _reset_confirming = false;
  
  // Load atSign and device info
  _atsign = ui_load_string(NVS_KEY_ATSIGN);
  _device = ui_load_string(NVS_KEY_DEVICE);
  
  // Clear log
  memset(_log_entries, 0, sizeof(_log_entries));
  _log_head = 0;

  // Clear throughput history
  memset(_tp_in, 0, sizeof(_tp_in));
  memset(_tp_out, 0, sizeof(_tp_out));
  _tp_head = 0;
  _prev_bytes_in = 0;
  _prev_bytes_out = 0;

  // Initial log entry
  _add_log_entry("Dashboard started", COLOR_SUCCESS);
  
  // Draw initial screen
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  
  _draw_header();
  _draw_stats_row1();
  _draw_stats_row2();
  _draw_log();
  _draw_graph();
  _draw_bottom_row();
  
  Serial.println("[ui_dashboard] Created");
}

void ui_dashboard_update(int active_relays, const char *daemon_state,
                         uint32_t total_tunnels, uint32_t total_pings,
                         uint32_t bytes_in, uint32_t bytes_out) {
  // Update state (only redraw if changed)
  bool stats_changed = false;
  
  if (_active_relays != active_relays) {
    _active_relays = active_relays;
    stats_changed = true;
  }
  
  if (strcmp(_daemon_state, daemon_state) != 0) {
    strncpy(_daemon_state, daemon_state, sizeof(_daemon_state) - 1);
    _daemon_state[sizeof(_daemon_state) - 1] = '\0';
    stats_changed = true;
  }
  
  if (_total_tunnels != total_tunnels || _total_pings != total_pings) {
    _total_tunnels = total_tunnels;
    _total_pings = total_pings;
    stats_changed = true;
  }

  // Record throughput sample (delta since last update)
  uint32_t delta_in  = bytes_in  - _prev_bytes_in;
  uint32_t delta_out = bytes_out - _prev_bytes_out;
  _prev_bytes_in  = bytes_in;
  _prev_bytes_out = bytes_out;

  _tp_in[_tp_head]  = delta_in;
  _tp_out[_tp_head] = delta_out;
  _tp_head = (_tp_head + 1) % GRAPH_SAMPLES;
  
  // Check reset confirmation timeout
  if (_reset_confirming && (millis() - _reset_confirm_ms > RESET_CONFIRM_TIMEOUT)) {
    _reset_confirming = false;
    _draw_bottom_row();
  }
  
  // Process event queue
  UiEvent evt;
  bool log_changed = false;
  
  while (ui_event_pop(&evt)) {
    switch (evt.type) {
      case UI_EVT_TUNNEL_OPEN:
        _add_log_entry(evt.text, COLOR_SUCCESS);
        log_changed = true;
        break;
        
      case UI_EVT_TUNNEL_CLOSE:
        _add_log_entry(evt.text, COLOR_TEXT_GREY);
        log_changed = true;
        break;
        
      case UI_EVT_PING:
        _add_log_entry(evt.text, COLOR_ACCENT);
        log_changed = true;
        break;
        
      case UI_EVT_DAEMON_STATE:
        _add_log_entry(evt.text, COLOR_TEXT_WHITE);
        log_changed = true;
        break;
        
      case UI_EVT_ERROR:
        _add_log_entry(evt.text, COLOR_ERROR);
        log_changed = true;
        break;
        
      default:
        break;
    }
  }
  
  // Always redraw stats (uptime/heap change constantly)
  _draw_stats_row1();
  _draw_stats_row2();
  _draw_graph();
  
  if (log_changed) {
    _draw_log();
  }
}

bool ui_dashboard_handle_touch(int16_t tx, int16_t ty) {
  // Check Reset button
  if (ui_touch_in_rect(tx, ty, RESET_BTN_X, RESET_BTN_Y, RESET_BTN_W, RESET_BTN_H)) {
    if (_reset_confirming) {
      // Second tap = confirmed
      Serial.println("[ui_dashboard] Reset confirmed!");
      if (_on_reset_cb) {
        _on_reset_cb();
      }
    } else {
      // First tap = ask for confirmation
      _reset_confirming = true;
      _reset_confirm_ms = millis();
      _draw_bottom_row();
      Serial.println("[ui_dashboard] Reset requested - tap again to confirm");
    }
    return true;
  }
  
  // If tapping elsewhere while confirming, cancel the confirmation
  if (_reset_confirming) {
    _reset_confirming = false;
    _draw_bottom_row();
    return true;
  }
  
  // Check LED button presses
  for (int i = 0; i < _led_preset_count; i++) {
    if (ui_touch_in_rect(tx, ty, _led_presets[i].x, _led_presets[i].y, 42, 24)) {
      ui_save_led_color(_led_presets[i].r, _led_presets[i].g, _led_presets[i].b);
      Serial.printf("[ui_dashboard] LED color: %s\\n", _led_presets[i].label);
      return true;
    }
  }
  
  return false;
}
