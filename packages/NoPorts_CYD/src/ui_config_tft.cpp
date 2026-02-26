/**
 * @file ui_config_tft.cpp
 * @brief Device configuration screen: worker keep-alive and relay settings.
 *
 * Simple toggle/counter screen — no keyboard needed.
 * Layout: header, config rows, bottom BACK/SAVE buttons.
 */

#include "ui_config_tft.h"
#include "ui_tft.h"
#include <Arduino.h>

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------
#define HEADER_H       28
#define ROW_Y_START    40
#define ROW_H          28
#define ROW_GAP         8
#define BTN_ROW_Y      (TFT_HEIGHT - 32)
#define BTN_ROW_H      28
#define CTRL_RIGHT     (TFT_WIDTH - 6)   // right edge of stepper controls

// Stepper control geometry (right-aligned per row)
#define STEP_PLUS_W    26
#define STEP_VAL_W     36
#define STEP_MINUS_W   26
#define STEP_GAP        3
#define STEP_PLUS_X    (CTRL_RIGHT - STEP_PLUS_W)
#define STEP_VAL_X     (STEP_PLUS_X - STEP_GAP - STEP_VAL_W)
#define STEP_MINUS_X   (STEP_VAL_X - STEP_GAP - STEP_MINUS_W)

// Bottom button layout: [BACK]  gap  [SAVE]
#define BACK_BTN_X     6
#define BACK_BTN_W     70
#define SAVE_BTN_X     (TFT_WIDTH - 6 - 90)
#define SAVE_BTN_W     90

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static void (*_on_save_cb)() = nullptr;

static int _keepalive_min = 4;   // 0 = off, 1-15 minutes
static int _max_subs      = 2;   // 1-5 relay sub-connections per session

// ---------------------------------------------------------------------------
// Drawing helpers
// ---------------------------------------------------------------------------

static void _draw_header() {
  TFT_eSPI &tft = ui_get_tft();
  ui_draw_rounded_rect(3, 3, TFT_WIDTH - 6, HEADER_H, 5, COLOR_BG_CARD);
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString("Config", 10, 3 + HEADER_H / 2, 4);
}

// Draw a labelled stepper row at y.
// label: left-aligned text; suffix: unit appended to value; val/min/max for range.
static void _draw_stepper(int y, const char *label, int val,
                          int vmin, int vmax, const char *off_label = nullptr) {
  TFT_eSPI &tft = ui_get_tft();

  // Row background
  tft.fillRect(3, y, TFT_WIDTH - 6, ROW_H, COLOR_BG_CARD);

  // Label
  tft.setTextColor(COLOR_TEXT_WHITE, COLOR_BG_CARD);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString(label, 10, y + ROW_H / 2, 2);

  // [-] button
  bool at_min = (val <= vmin);
  ui_draw_rounded_rect(STEP_MINUS_X, y + 2, STEP_MINUS_W, ROW_H - 4, 3,
                       at_min ? 0x2104 : COLOR_BUTTON_BG);
  tft.setTextColor(at_min ? COLOR_TEXT_GREY : COLOR_TEXT_WHITE);
  tft.setTextDatum(MC_DATUM);
  tft.drawString("-", STEP_MINUS_X + STEP_MINUS_W / 2, y + ROW_H / 2, 2);

  // Value box
  tft.fillRect(STEP_VAL_X, y + 2, STEP_VAL_W, ROW_H - 4, COLOR_BG_DARK);
  char vbuf[10];
  if (off_label && val == 0) {
    snprintf(vbuf, sizeof(vbuf), "%s", off_label);
  } else {
    snprintf(vbuf, sizeof(vbuf), "%d", val);
  }
  tft.setTextColor(COLOR_ACCENT, COLOR_BG_DARK);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(vbuf, STEP_VAL_X + STEP_VAL_W / 2, y + ROW_H / 2, 2);

  // [+] button
  bool at_max = (val >= vmax);
  ui_draw_rounded_rect(STEP_PLUS_X, y + 2, STEP_PLUS_W, ROW_H - 4, 3,
                       at_max ? 0x2104 : COLOR_BUTTON_BG);
  tft.setTextColor(at_max ? COLOR_TEXT_GREY : COLOR_TEXT_WHITE);
  tft.setTextDatum(MC_DATUM);
  tft.drawString("+", STEP_PLUS_X + STEP_PLUS_W / 2, y + ROW_H / 2, 2);
}

static void _draw_rows() {
  TFT_eSPI &tft = ui_get_tft();
  int y = ROW_Y_START;

  // ── Worker keep-alive ──
  _draw_stepper(y, "Worker KA (min):", _keepalive_min, 0, 15, "off");
  y += ROW_H + ROW_GAP;

  // hint line
  tft.setTextColor(COLOR_TEXT_GREY, COLOR_BG_DARK);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString("Heartbeat to keep atServer TLS alive", 10, y, 1);
  y += 12;

  // ── Concurrent TCP sessions per relay ──
  _draw_stepper(y, "TCP clients:", _max_subs, 1, 6);
}

static void _draw_buttons() {
  TFT_eSPI &tft = ui_get_tft();

  // BACK
  ui_draw_rounded_rect(BACK_BTN_X, BTN_ROW_Y, BACK_BTN_W, BTN_ROW_H, 5, COLOR_BUTTON_BG);
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(1);
  tft.drawString("BACK", BACK_BTN_X + BACK_BTN_W / 2, BTN_ROW_Y + BTN_ROW_H / 2, 2);

  // SAVE
  ui_draw_rounded_rect(SAVE_BTN_X, BTN_ROW_Y, SAVE_BTN_W, BTN_ROW_H, 5, COLOR_SUCCESS);
  tft.setTextColor(COLOR_TEXT_WHITE);
  tft.setTextDatum(MC_DATUM);
  tft.drawString("SAVE", SAVE_BTN_X + SAVE_BTN_W / 2, BTN_ROW_Y + BTN_ROW_H / 2, 2);
}

static void _draw_screen() {
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  _draw_header();
  _draw_rows();
  _draw_buttons();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void ui_config_create(void (*on_save)()) {
  _on_save_cb = on_save;

  // Load from NVS
  String ka = ui_load_string(NVS_KEY_WORKER_KEEPALIVE);
  _keepalive_min = (ka.length() > 0) ? (int)ka.toInt() : 4;
  if (_keepalive_min < 0)  _keepalive_min = 0;
  if (_keepalive_min > 15) _keepalive_min = 15;

  String ms = ui_load_string(NVS_KEY_MAX_RELAYS);
  _max_subs = (ms.length() > 0) ? (int)constrain(ms.toInt(), 1, 5) : 2;

  _draw_screen();
}

void ui_config_update() {
  // Nothing to poll; all interaction is touch-driven.
}

bool ui_config_handle_touch(int16_t tx, int16_t ty) {
  int y = ROW_Y_START;

  // Worker KA stepper row
  if (ty >= y && ty < y + ROW_H) {
    if (ui_touch_in_rect(tx, ty, STEP_MINUS_X, y, STEP_MINUS_W, ROW_H)) {
      if (_keepalive_min > 0) {
        _keepalive_min--;
        _draw_stepper(y, "Worker KA (min):", _keepalive_min, 0, 15, "off");
      }
      return true;
    }
    if (ui_touch_in_rect(tx, ty, STEP_PLUS_X, y, STEP_PLUS_W, ROW_H)) {
      if (_keepalive_min < 15) {
        _keepalive_min++;
        _draw_stepper(y, "Worker KA (min):", _keepalive_min, 0, 15, "off");
      }
      return true;
    }
  }
  y += ROW_H + ROW_GAP + 12;  // skip KA row + hint text

  // Max sessions stepper row
  if (ty >= y && ty < y + ROW_H) {
    if (ui_touch_in_rect(tx, ty, STEP_MINUS_X, y, STEP_MINUS_W, ROW_H)) {
      if (_max_subs > 1) {
        _max_subs--;
        _draw_stepper(y, "TCP clients:", _max_subs, 1, 6);
      }
      return true;
    }
    if (ui_touch_in_rect(tx, ty, STEP_PLUS_X, y, STEP_PLUS_W, ROW_H)) {
      if (_max_subs < 6) {
        _max_subs++;
        _draw_stepper(y, "TCP clients:", _max_subs, 1, 6);
      }
      return true;
    }
  }

  // BACK button
  if (ui_touch_in_rect(tx, ty, BACK_BTN_X, BTN_ROW_Y, BACK_BTN_W, BTN_ROW_H)) {
    // Reload from NVS (discard changes) then call on_save to return to dashboard
    String ka = ui_load_string(NVS_KEY_WORKER_KEEPALIVE);
    _keepalive_min = (ka.length() > 0) ? (int)ka.toInt() : 4;
    String ms = ui_load_string(NVS_KEY_MAX_RELAYS);
    _max_subs = (ms.length() > 0) ? (int)constrain(ms.toInt(), 1, 6) : 2;
    Serial.println("[config] BACK — changes discarded");
    if (_on_save_cb) _on_save_cb();
    return true;
  }

  // SAVE button
  if (ui_touch_in_rect(tx, ty, SAVE_BTN_X, BTN_ROW_Y, SAVE_BTN_W, BTN_ROW_H)) {
    char ka_str[4];
    snprintf(ka_str, sizeof(ka_str), "%d", _keepalive_min);
    ui_save_string(NVS_KEY_WORKER_KEEPALIVE, ka_str);
    char ms_str[4];
    snprintf(ms_str, sizeof(ms_str), "%d", _max_subs);
    ui_save_string(NVS_KEY_MAX_RELAYS, ms_str);
    Serial.printf("[config] Saved: worker keepalive=%d min, max sessions=%d\n",
                  _keepalive_min, _max_subs);
    if (_on_save_cb) _on_save_cb();
    return true;
  }

  return false;
}
