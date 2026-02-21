/**
 * @file User_Setup.h
 * @brief TFT_eSPI configuration for CYD (ESP32-2432S028R)
 *
 * This file configures TFT_eSPI for the ILI9341 display and XPT2046 touch
 * controller on the CYD (Cheap Yellow Display) board.
 */

// Display driver
#define ILI9341_DRIVER

// ESP32 Display pins (HSPI)
#define TFT_MISO 12
#define TFT_MOSI 13
#define TFT_SCLK 14
#define TFT_CS   15
#define TFT_DC   2
#define TFT_RST  -1  // Connected to ESP32 reset

// Touch controller pins (shared SPI bus)
#define TOUCH_CS 33

// Display size
#define TFT_WIDTH  240
#define TFT_HEIGHT 320

// Fonts
#define LOAD_GLCD   // Font 1. Original Adafruit 8 pixel font
#define LOAD_FONT2  // Font 2. Small 16 pixel high font
#define LOAD_FONT4  // Font 4. Medium 26 pixel high font
#define LOAD_FONT6  // Font 6. Large 48 pixel font
#define LOAD_FONT7  // Font 7. 7 segment 48 pixel font
#define LOAD_FONT8  // Font 8. Large 75 pixel font
#define LOAD_GFXFF  // FreeFonts

#define SMOOTH_FONT

// SPI frequency
#define SPI_FREQUENCY       40000000
#define SPI_READ_FREQUENCY  16000000
#define SPI_TOUCH_FREQUENCY  2500000
