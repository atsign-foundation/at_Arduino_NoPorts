/**
 * @file ui_wifi_tft.h
 * @brief WiFi setup screen using TFT_eSPI
 */

#ifndef UI_WIFI_TFT_H
#define UI_WIFI_TFT_H

#include <Arduino.h>

/**
 * @brief Create and show the WiFi setup screen
 *
 * Displays available WiFi networks and allows selection/password entry
 *
 * @param on_connected Callback invoked when WiFi connects successfully
 */
void ui_wifi_create(void (*on_connected)());

/**
 * @brief Update the WiFi screen (handle scanning, connection status, password entry)
 * Call this from the main loop while on the WiFi screen
 */
void ui_wifi_update();

/**
 * @brief Handle touch input on WiFi screen
 * @return true if touch was handled
 */
bool ui_wifi_handle_touch(int16_t tx, int16_t ty);

/**
 * @brief Attempt to auto-connect using saved credentials
 * @return true if connection succeeded within timeout
 */
bool ui_wifi_auto_connect(int timeout_ms = 10000);

/**
 * @brief Get the current WiFi IP address as a string
 */
String ui_wifi_get_ip();

#endif // UI_WIFI_TFT_H
