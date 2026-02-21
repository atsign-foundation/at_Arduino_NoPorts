/**
 * @file ui_dashboard_tft.h
 * @brief Dashboard screen using TFT_eSPI (memory-efficient)
 */

#ifndef UI_DASHBOARD_TFT_H
#define UI_DASHBOARD_TFT_H

#include <Arduino.h>

/**
 * @brief Initialize and display the dashboard screen
 * @param on_reset Callback when user presses the Reset button
 */
void ui_dashboard_create(void (*on_reset)() = nullptr);

/**
 * @brief Update dashboard with current status
 * Called from main loop to refresh stats and process event queue
 */
void ui_dashboard_update(int active_relays, const char *daemon_state,
                         uint32_t total_tunnels, uint32_t total_pings,
                         uint32_t bytes_in = 0, uint32_t bytes_out = 0);

/**
 * @brief Handle touch input on dashboard
 * @return true if touch was handled
 */
bool ui_dashboard_handle_touch(int16_t tx, int16_t ty);

#endif // UI_DASHBOARD_TFT_H
