/**
 * @file ui_config_tft.cpp
 * @brief Device configuration screen: worker keep-alive, relay settings and
 *        the root server spec.
 *
 * Steppers are touch-driven counters; the root server row opens an inline
 * keyboard editor (the only free-text setting on this screen).
 * Layout: header, config rows, bottom BACK/SAVE buttons.
 */

#include "ui_config_tft.h"
#include "ui_tft.h"
#include <Arduino.h>
#include "noports/noports_daemon.h"  // NOPORTS_MAX_RELAYS

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

// Root server editor keyboard (same geometry as the enrollment screen)
#define KB_TOP_Y       125
#define KEYS_PER_ROW   10
#define KEY_WIDTH      30
#define KEY_HEIGHT     18
#define KEY_SPACING     1

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static void (*_on_save_cb)() = nullptr;

static int  _keepalive_min = 4;   // 0 = off, 1-15 minutes
static int  _max_subs      = NOPORTS_MAX_RELAYS;   // 1-NOPORTS_MAX_RELAYS relay sub-connections per session
// Root server spec: host[:port] or proxy:host[:port] for 443-only networks
static char _root_spec[128] = "";
static bool _editing_root   = false;

static const char *DEFAULT_ROOT_SPEC = "root.atsign.org";

// Editor keyboard — no SPACE key: spaces are not valid in a root server
// spec, and the proxy form needs ':' instead.
static const char* _kb_keys[] = {
  "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
  "q", "w", "e", "r", "t", "y", "u", "i", "o", "p",
  "a", "s", "d", "f", "g", "h", "j", "k", "l", "@",
  "z", "x", "c", "v", "b", "n", "m", "_", "-", ".",
  "DEL", ":", "DONE"
};
static const int _kb_key_count = sizeof(_kb_keys) / sizeof(_kb_keys[0]);

// ---------------------------------------------------------------------------
// Drawing helpers
// ---------------------------------------------------------------------------

static void _draw_header(const char *title) {
  TFT_eSPI &tft = ui_get_tft();
  ui_draw_rounded_rect(3, 3, TFT_WIDTH - 6, HEADER_H, 5, COLOR_BG_CARD);
  tft.setTextColor(COLOR_PRIMARY);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString(title, 10, 3 + HEADER_H / 2, 4);
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

// Y positions of the three config rows
static int _ka_row_y()   { return ROW_Y_START; }
static int _subs_row_y() { return _ka_row_y() + ROW_H + ROW_GAP + 12; }  // +12 for hint text
static int _root_row_y() { return _subs_row_y() + ROW_H + ROW_GAP; }

// Root server row: label + tappable value box (opens the inline editor)
static void _draw_root_row() {
  TFT_eSPI &tft = ui_get_tft();
  int y = _root_row_y();

  // Row background
  tft.fillRect(3, y, TFT_WIDTH - 6, ROW_H, COLOR_BG_CARD);

  // Label
  tft.setTextColor(COLOR_TEXT_WHITE, COLOR_BG_CARD);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString("Root:", 10, y + ROW_H / 2, 2);

  // Value box (tap to edit)
  int box_x = 55;
  int box_w = CTRL_RIGHT - box_x;
  tft.fillRect(box_x, y + 2, box_w, ROW_H - 4, COLOR_BG_DARK);

  // Show the tail if the spec is wider than the box (the interesting part
  // of a proxy spec is the host:port at the end)
  const char *text = _root_spec;
  int max_w = box_w - 8;
  int skip = 0;
  while (tft.textWidth(text + skip, 2) > max_w && text[skip]) skip++;
  tft.setTextColor(COLOR_ACCENT, COLOR_BG_DARK);
  tft.setTextDatum(ML_DATUM);
  tft.drawString(text + skip, box_x + 4, y + ROW_H / 2, 2);

  // Hint line below
  tft.setTextColor(COLOR_TEXT_GREY, COLOR_BG_DARK);
  tft.setTextDatum(ML_DATUM);
  tft.drawString("Tap to edit. proxy:host:443 for 443-only networks", 10, y + ROW_H + 6, 1);
}

static void _draw_rows() {
  TFT_eSPI &tft = ui_get_tft();

  // ── Worker keep-alive ──
  int y = _ka_row_y();
  _draw_stepper(y, "Worker KA (min):", _keepalive_min, 0, 15, "off");

  // hint line
  tft.setTextColor(COLOR_TEXT_GREY, COLOR_BG_DARK);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString("Heartbeat to keep atServer TLS alive", 10, y + ROW_H + ROW_GAP, 1);

  // ── Concurrent TCP sessions per relay ──
  _draw_stepper(_subs_row_y(), "TCP clients:", _max_subs, 1, NOPORTS_MAX_RELAYS);

  // ── Root server spec ──
  _draw_root_row();
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
  _draw_header("Config");
  _draw_rows();
  _draw_buttons();
}

// ---------------------------------------------------------------------------
// Root server inline editor
// ---------------------------------------------------------------------------

static void _draw_editor_value() {
  TFT_eSPI &tft = ui_get_tft();
  int y = 44;

  ui_draw_rounded_rect(5, y, TFT_WIDTH - 10, 20, 4, COLOR_BG_CARD);

  // Show the tail so the cursor position stays visible
  const char *text = _root_spec;
  int max_w = TFT_WIDTH - 26;
  int skip = 0;
  while (tft.textWidth(text + skip, 2) > max_w && text[skip]) skip++;

  tft.setTextColor(COLOR_TEXT_WHITE, COLOR_BG_CARD);
  tft.setTextDatum(ML_DATUM);
  tft.setTextSize(1);
  tft.drawString(text + skip, 10, y + 10, 2);

  // Cursor
  int cx = 10 + tft.textWidth(text + skip, 2);
  if (cx > TFT_WIDTH - 12) cx = TFT_WIDTH - 12;
  tft.drawLine(cx, y + 3, cx, y + 17, COLOR_PRIMARY);
}

static void _draw_editor_keyboard() {
  TFT_eSPI &tft = ui_get_tft();
  tft.fillRect(0, KB_TOP_Y, TFT_WIDTH, TFT_HEIGHT - KB_TOP_Y, COLOR_BG_DARK);

  int key_idx = 0;
  int row = 0;
  int x_start = 5;

  for (int i = 0; i < _kb_key_count; i++) {
    int col = key_idx % KEYS_PER_ROW;
    int x = x_start + col * (KEY_WIDTH + KEY_SPACING);
    int y = KB_TOP_Y + row * (KEY_HEIGHT + KEY_SPACING) + 2;

    // Wide keys: DEL=3cols, ':'=4cols, DONE=3cols (total 10 = full row)
    int key_w = KEY_WIDTH;
    int col_span = 1;
    if (strcmp(_kb_keys[i], "DEL") == 0 || strcmp(_kb_keys[i], "DONE") == 0) {
      key_w = KEY_WIDTH * 3 + KEY_SPACING * 2;
      col_span = 3;
    } else if (strcmp(_kb_keys[i], ":") == 0) {
      key_w = KEY_WIDTH * 4 + KEY_SPACING * 3;
      col_span = 4;
    }

    uint16_t bg = (strcmp(_kb_keys[i], "DONE") == 0) ? COLOR_SUCCESS : COLOR_BUTTON_BG;
    ui_draw_rounded_rect(x, y, key_w, KEY_HEIGHT, 3, bg);

    tft.setTextColor(COLOR_TEXT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.setTextSize(1);
    tft.drawString(_kb_keys[i], x + key_w / 2, y + KEY_HEIGHT / 2, 2);

    key_idx += col_span;
    if (key_idx >= KEYS_PER_ROW) {
      row++;
      key_idx = 0;
    }
  }
}

static void _draw_editor_screen() {
  TFT_eSPI &tft = ui_get_tft();
  tft.fillScreen(COLOR_BG_DARK);
  _draw_header("Root server");
  _draw_editor_value();

  // Hints
  tft.setTextColor(COLOR_TEXT_GREY, COLOR_BG_DARK);
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);
  tft.drawString("atDirectory host, optional :port (default 64).", 8, 72, 1);
  tft.drawString("proxy:host:port connects the atServer via a", 8, 84, 1);
  tft.drawString("reverse proxy - for 443-only networks, e.g.", 8, 96, 1);
  tft.drawString("proxy:proxy0001.atsign.org:443", 8, 108, 1);

  _draw_editor_keyboard();
}

static bool _check_editor_press(int16_t tx, int16_t ty) {
  int key_idx = 0;
  int row = 0;
  int x_start = 5;

  for (int i = 0; i < _kb_key_count; i++) {
    int col = key_idx % KEYS_PER_ROW;
    int x = x_start + col * (KEY_WIDTH + KEY_SPACING);
    int y = KB_TOP_Y + row * (KEY_HEIGHT + KEY_SPACING) + 2;

    int key_w = KEY_WIDTH;
    int col_span = 1;
    if (strcmp(_kb_keys[i], "DEL") == 0 || strcmp(_kb_keys[i], "DONE") == 0) {
      key_w = KEY_WIDTH * 3 + KEY_SPACING * 2;
      col_span = 3;
    } else if (strcmp(_kb_keys[i], ":") == 0) {
      key_w = KEY_WIDTH * 4 + KEY_SPACING * 3;
      col_span = 4;
    }

    if (ui_touch_in_rect(tx, ty, x, y, key_w, KEY_HEIGHT)) {
      size_t len = strlen(_root_spec);

      if (strcmp(_kb_keys[i], "DEL") == 0) {
        if (len > 0) _root_spec[len - 1] = '\0';
        _draw_editor_value();
      } else if (strcmp(_kb_keys[i], "DONE") == 0) {
        _editing_root = false;
        _draw_screen();
      } else {
        if (len < sizeof(_root_spec) - 1) {
          _root_spec[len] = _kb_keys[i][0];
          _root_spec[len + 1] = '\0';
        }
        _draw_editor_value();
      }
      return true;
    }

    key_idx += col_span;
    if (key_idx >= KEYS_PER_ROW) {
      row++;
      key_idx = 0;
    }
  }

  return true;  // consume all touches while the editor is open
}

// ---------------------------------------------------------------------------
// NVS load helper
// ---------------------------------------------------------------------------

static void _load_from_nvs() {
  String ka = ui_load_string(NVS_KEY_WORKER_KEEPALIVE);
  _keepalive_min = (ka.length() > 0) ? (int)ka.toInt() : 4;
  if (_keepalive_min < 0)  _keepalive_min = 0;
  if (_keepalive_min > 15) _keepalive_min = 15;

  String ms = ui_load_string(NVS_KEY_MAX_RELAYS);
  _max_subs = (ms.length() > 0) ? (int)constrain(ms.toInt(), 1, NOPORTS_MAX_RELAYS) : NOPORTS_MAX_RELAYS;

  String root = ui_load_string(NVS_KEY_ROOT);
  strncpy(_root_spec, root.length() ? root.c_str() : DEFAULT_ROOT_SPEC,
          sizeof(_root_spec) - 1);
  _root_spec[sizeof(_root_spec) - 1] = '\0';
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void ui_config_create(void (*on_save)()) {
  _on_save_cb = on_save;
  _editing_root = false;
  _load_from_nvs();
  _draw_screen();
}

void ui_config_update() {
  // Nothing to poll; all interaction is touch-driven.
}

bool ui_config_handle_touch(int16_t tx, int16_t ty) {
  // Inline root server editor swallows everything while open
  if (_editing_root) {
    return _check_editor_press(tx, ty);
  }

  // Worker KA stepper row
  int y = _ka_row_y();
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

  // Max sessions stepper row
  y = _subs_row_y();
  if (ty >= y && ty < y + ROW_H) {
    if (ui_touch_in_rect(tx, ty, STEP_MINUS_X, y, STEP_MINUS_W, ROW_H)) {
      if (_max_subs > 1) {
        _max_subs--;
        _draw_stepper(y, "TCP clients:", _max_subs, 1, NOPORTS_MAX_RELAYS);
      }
      return true;
    }
    if (ui_touch_in_rect(tx, ty, STEP_PLUS_X, y, STEP_PLUS_W, ROW_H)) {
      if (_max_subs < NOPORTS_MAX_RELAYS) {
        _max_subs++;
        _draw_stepper(y, "TCP clients:", _max_subs, 1, NOPORTS_MAX_RELAYS);
      }
      return true;
    }
  }

  // Root server row — tap anywhere in the row opens the editor
  y = _root_row_y();
  if (ui_touch_in_rect(tx, ty, 3, y, TFT_WIDTH - 6, ROW_H)) {
    _editing_root = true;
    _draw_editor_screen();
    return true;
  }

  // BACK button
  if (ui_touch_in_rect(tx, ty, BACK_BTN_X, BTN_ROW_Y, BACK_BTN_W, BTN_ROW_H)) {
    // Reload from NVS (discard changes) then call on_save to return to dashboard
    _load_from_nvs();
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
    // Persist the root spec only when it differs from the default, so a
    // default-valued field doesn't shadow a future default change
    ui_save_string(NVS_KEY_ROOT,
                   (strcmp(_root_spec, DEFAULT_ROOT_SPEC) == 0) ? "" : _root_spec);
    Serial.printf("[config] Saved: worker keepalive=%d min, max sessions=%d, root=%s\n",
                  _keepalive_min, _max_subs, _root_spec);
    if (_on_save_cb) _on_save_cb();
    return true;
  }

  return false;
}
