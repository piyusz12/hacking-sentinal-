/*
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║   ESP32-S3 SENTINEL — Network Guardian Firmware v4.1 (PRO)       ║
 * ║                                                                  ║
 * ║   Core 0  →  802.11 Promiscuous Sniffer (ISR only)               ║
 * ║   Core 1  →  WiFi / WS / OLED / I2S Mic / I2S Spk / RGB / BZR   ║
 * ║                                                                  ║
 * ║   HARDWARE:                                                      ║
 * ║   ► SSD1306 OLED 128x64  (I2C: SDA=8, SCL=9)                    ║
 * ║   ► WS2812B RGB NeoPixel (GPIO 48)                               ║
 * ║   ► Piezo Buzzer         (PWM: GPIO 15)                          ║
 * ║   ► INMP441 I2S Mic      (I2S0: BCK=41, WS=42, DATA=2)          ║
 * ║   ► MAX98357A I2S Amp    (I2S1: BCK=4, WS=5, DATA=6)            ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_NeoPixel.h>
#include "driver/i2s.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   WIFI + BACKEND CONFIG (UPDATE THESE!)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const char* WIFI_SSID = "Drop It Like it's Hotspot";
const char* WIFI_PASS = "smartbot12";
const char* WS_HOST   = "192.168.1.100";   // ← Your FastAPI laptop IP (IPv4)
const int   WS_PORT   = 8000;
const char* WS_PATH   = "/ws/sentinel";
#define HOME_CHANNEL  6

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   HARDWARE PIN DEFINITIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 1. SSD1306 OLED (I2C)
#define OLED_SDA    8
#define OLED_SCL    9
#define OLED_ADDR   0x3C
#define OLED_W      128
#define OLED_H      64

// 2. INMP441 Microphone (I2S_NUM_0 RX)
#define MIC_I2S_PORT  I2S_NUM_0
#define MIC_BCK       41
#define MIC_WS        42
#define MIC_DATA      2

// 3. MAX98357A Speaker (I2S_NUM_1 TX)
#define SPK_I2S_PORT  I2S_NUM_1
#define SPK_BCK       4
#define SPK_WS        5
#define SPK_DATA      6

// 4. Piezo Buzzer (PWM)
#define BUZZER_PIN    15

// 5. RGB NeoPixel (WS2812B)
#define RGB_PIN     48
#define NUMPIXELS   1

Adafruit_NeoPixel pixels(NUMPIXELS, RGB_PIN, NEO_GRB + NEO_KHZ800);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   DETECTION THRESHOLDS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#define DEAUTH_THRESHOLD    5
#define PROBE_THRESHOLD     25
#define DOS_PKT_THRESHOLD   600
#define DETECTION_WINDOW_MS 3000
#define TELEMETRY_MS        2000
#define VOICE_THRESHOLD     5000
#define VOICE_HOLD_MS       300

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   SYSTEM STATE + SHARED GLOBALS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
enum SentinelState { ST_BOOT, ST_SAFE, ST_ALERT, ST_MONITORING };
volatile SentinelState sysState = ST_BOOT;

char g_alert_type[32] = "";
char g_alert_mac[18]  = "";
int8_t g_alert_rssi   = -50;
uint8_t g_alert_ch    = 6;
int  g_alert_pkts     = 0;

bool hw_oled_ok = false;
bool hw_spk_ok  = false;
bool hw_mic_ok  = false;
volatile bool voice_trigger = false;

bool oled_blink = false;
unsigned long last_oled_update_ms = 0;
unsigned long last_rgb_update_ms  = 0;
bool rgb_strobe_state = false;
int  radar_angle      = 0;
unsigned long alert_start_ms = 0;      // Track when alert started
unsigned long monitoring_start_ms = 0; // Track when monitoring started

struct ThreatAlert {
  char    type[32];
  char    mac[18];
  int8_t  rssi;
  uint8_t channel;
  int     count;
};

QueueHandle_t alertQueue;
portMUX_TYPE cntMux = portMUX_INITIALIZER_UNLOCKED;

volatile int cnt_total  = 0;
volatile int cnt_mgmt   = 0;
volatile int cnt_data   = 0;
volatile int cnt_deauth = 0;
volatile int cnt_probe  = 0;

unsigned long last_telemetry_ms = 0;
unsigned long last_window_ms    = 0;
uint8_t current_channel = HOME_CHANNEL;
bool ws_connected = false;

WebSocketsClient webSocket;
Adafruit_SSD1306 display(OLED_W, OLED_H, &Wire, -1);

typedef struct __attribute__((packed)) {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];   // Source MAC
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
} mac_hdr_t;

inline void fmtMAC(const uint8_t* addr, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   BUZZER — PWM TONE GENERATION (always available, no I2S)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
void buzzerTone(int freqHz, int durationMs) {
  if (freqHz > 0) {
    tone(BUZZER_PIN, freqHz, durationMs);
    delay(durationMs);
  } else {
    delay(durationMs);
  }
  noTone(BUZZER_PIN);
}

void buzzerBootChime() {
  buzzerTone(523, 80);  // C5
  buzzerTone(659, 80);  // E5
  buzzerTone(784, 120); // G5
  buzzerTone(1047, 150);// C6
}

void buzzerAlertSiren() {
  // Aggressive rising siren — matches UI "ALERT" state red flash
  for (int i = 0; i < 3; i++) {
    buzzerTone(2200, 80);
    buzzerTone(0, 30);
    buzzerTone(2800, 80);
    buzzerTone(0, 30);
  }
}

void buzzerAllClear() {
  // Descending major triad — signals "MONITORING / AI Resolved"
  buzzerTone(784, 100);  // G5
  buzzerTone(659, 100);  // E5
  buzzerTone(523, 180);  // C5
}

void buzzerVoiceAck() {
  // Two quick chirps — voice command acknowledged
  buzzerTone(1500, 50);
  buzzerTone(0, 30);
  buzzerTone(2000, 50);
}

void buzzerWsConnect() {
  // Short ascending beep — WebSocket connected
  buzzerTone(800, 60);
  buzzerTone(1200, 80);
}

void buzzerWsDisconnect() {
  // Low descending — WebSocket lost
  buzzerTone(600, 100);
  buzzerTone(300, 150);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   RGB LED — THREAT-COLORED NeoPixel CONTROLLER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
void setRGB(uint8_t r, uint8_t g, uint8_t b) {
  pixels.setPixelColor(0, pixels.Color(r, g, b));
  pixels.show();
}

// Map threat type to RGB color matching the UI frontend preset palette
void getThreatColor(const char* type, uint8_t &r, uint8_t &g, uint8_t &b) {
  String t = String(type);
  t.toUpperCase();
  if (t.indexOf("DEAUTH") != -1)      { r=255; g=71;  b=87;  } // #ff4757
  else if (t.indexOf("EVIL") != -1 ||
           t.indexOf("TWIN") != -1)    { r=255; g=107; b=129; } // #ff6b81
  else if (t.indexOf("BEACON") != -1)  { r=255; g=159; b=67;  } // #ff9f43
  else if (t.indexOf("PROBE") != -1)   { r=76;  g=201; b=240; } // #4cc9f0
  else if (t.indexOf("KARMA") != -1)   { r=123; g=97;  b=255; } // #7b61ff
  else if (t.indexOf("PMKID") != -1)   { r=6;   g=214; b=160; } // #06d6a0
  else                                 { r=255; g=0;   b=0;   } // Default red
}

void updateRGB() {
  unsigned long now = millis();

  if (sysState == ST_BOOT) {
    // Pulsing blue during boot
    float intensity = (sin(now / 300.0) + 1.0) * 0.5 * 100.0;
    setRGB(0, 0, (uint8_t)intensity);
  }
  else if (sysState == ST_SAFE) {
    // Breathing green — calm heartbeat
    float intensity = (sin(now / 1500.0) + 1.0) * 0.5 * 50.0 + 5.0;
    setRGB(0, (uint8_t)intensity, 0);
  }
  else if (sysState == ST_ALERT) {
    // Police strobe: Threat color ↔ OFF at 50ms (very aggressive)
    if (now - last_rgb_update_ms > 50) {
      rgb_strobe_state = !rgb_strobe_state;
      if (rgb_strobe_state) {
        uint8_t r, g, b;
        getThreatColor(g_alert_type, r, g, b);
        setRGB(r, g, b);
      } else {
        setRGB(0, 0, 0);
      }
      last_rgb_update_ms = now;
    }
  }
  else if (sysState == ST_MONITORING) {
    // Fast pulsing orange — AI processing
    float intensity = (exp(sin(now / 400.0 * PI)) - 0.36787944) * 108.0;
    setRGB((uint8_t)intensity, (uint8_t)(intensity * 0.4), 0);
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   OLED — PROFESSIONAL ANIMATED DISPLAY SCREENS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
bool initOLED() {
  Wire.begin(OLED_SDA, OLED_SCL);
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("[OLED] NOT FOUND!");
    return false;
  }
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.cp437(true);
  Serial.println("[OLED] Initialized OK");
  return true;
}

// ── Animated Radar Sweep (drawn on SAFE screen)
void drawRadar(int cx, int cy, int radius, int angle) {
  display.drawCircle(cx, cy, radius, SSD1306_WHITE);
  display.drawCircle(cx, cy, radius / 2, SSD1306_WHITE);
  display.drawPixel(cx, cy, SSD1306_WHITE);
  float rad = angle * PI / 180.0;
  int ex = cx + (int)(radius * cos(rad));
  int ey = cy + (int)(radius * sin(rad));
  display.drawLine(cx, cy, ex, ey, SSD1306_WHITE);
  // Draw fading trail (3 previous positions)
  for (int i = 1; i <= 3; i++) {
    float trad = (angle - i * 15) * PI / 180.0;
    int tx = cx + (int)((radius - 2) * cos(trad));
    int ty = cy + (int)((radius - 2) * sin(trad));
    display.drawPixel(tx, ty, SSD1306_WHITE);
  }
}

// ── Crosshair Target Lock (drawn on ALERT screen)
void drawCrosshair(int cx, int cy, int size) {
  display.drawLine(cx - size, cy, cx + size, cy, SSD1306_WHITE);
  display.drawLine(cx, cy - size, cx, cy + size, SSD1306_WHITE);
  display.drawCircle(cx, cy, size - 2, SSD1306_WHITE);
  display.drawCircle(cx, cy, size / 2, SSD1306_WHITE);
}

// ── BOOT SCREEN: Progress bar with stage labels
void oledBoot(int progress, const char* stage) {
  display.clearDisplay();

  // Header
  display.setTextSize(1);
  display.setCursor(4, 0);
  display.print(F("\x10 ")); // ► character
  display.println(F("SENTINEL v4.1"));
  display.drawLine(0, 9, 127, 9, SSD1306_WHITE);

  // Device info
  display.setCursor(4, 13);  display.println(F("ESP32-S3 Dual-Core"));
  display.setCursor(4, 23);  display.println(F("802.11 WIDS + AI SOC"));

  // Current stage
  display.setCursor(4, 36);
  display.print(F("> "));
  display.println(stage);

  // Progress bar
  display.drawRect(4, 50, 120, 12, SSD1306_WHITE);
  int fillW = (int)((long)progress * 116 / 100);
  if (fillW > 0) display.fillRect(6, 52, fillW, 8, SSD1306_WHITE);

  // Percentage
  char pct[6]; snprintf(pct, sizeof(pct), "%d%%", progress);
  display.setCursor(105, 38); display.print(pct);

  display.display();
}

// ── SAFE SCREEN: Live telemetry + animated radar + WS status
void oledSafe(int pktRate, int rssi) {
  display.clearDisplay();
  display.invertDisplay(false);

  // Animated radar in top-right corner
  radar_angle = (radar_angle + 20) % 360;
  drawRadar(108, 20, 14, radar_angle);

  // Header bar
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println(F("SENTINEL ACTIVE"));
  display.drawLine(0, 9, 127, 9, SSD1306_WHITE);

  // Live metrics
  display.setCursor(0, 13); display.printf("PKT/S : %d", pktRate);
  display.setCursor(0, 23); display.printf("RSSI  : %d dBm", rssi);
  display.setCursor(0, 33); display.printf("CH: %d | WS: %s", current_channel, ws_connected ? "LIVE" : "DOWN");

  // IP Address
  if (WiFi.status() == WL_CONNECTED) {
    display.setCursor(0, 43);
    display.printf("IP: %s", WiFi.localIP().toString().c_str());
  }

  // Status bar at bottom
  display.drawLine(0, 53, 127, 53, SSD1306_WHITE);
  display.setCursor(6, 56);
  display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);  // Inverted text
  display.print(F("  [ SYSTEM SECURE ]  "));
  display.setTextColor(SSD1306_WHITE);                  // Reset

  display.display();
}

// ── ALERT SCREEN: Flashing attack display + crosshair + threat info
void oledAlert(const char* type, const char* mac, int8_t rssi, uint8_t ch, int pkts, bool blink) {
  display.clearDisplay();
  display.invertDisplay(blink);  // Full display inversion for strobe effect

  // Blinking ATTACK header
  display.setTextSize(2);
  display.setCursor(4, 0);
  display.println(F("!!ATTACK!!"));

  display.drawLine(0, 18, 127, 18, SSD1306_WHITE);

  // Crosshair graphic in corner
  drawCrosshair(112, 35, 10);

  // Threat details
  display.setTextSize(1);
  char shortType[18]; strncpy(shortType, type, 17); shortType[17] = '\0';
  display.setCursor(0, 21); display.println(shortType);

  display.setCursor(0, 31); display.printf("SRC: %s", mac);
  display.setCursor(0, 41); display.printf("CH:%d RSSI:%ddBm", ch, rssi);

  // Bottom action bar
  display.drawLine(0, 51, 127, 51, SSD1306_WHITE);
  display.setCursor(0, 54);
  if (blink) {
    display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    display.print(F(" > AI ENGAGING... < "));
    display.setTextColor(SSD1306_WHITE);
  } else {
    display.print(F("  ADMIN NOTIFIED"));
  }

  display.display();
}

// ── MONITORING SCREEN: AI analysis progress bar + threat summary
void oledMonitoring(const char* type) {
  display.clearDisplay();
  display.invertDisplay(false);

  // Header
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println(F("AI FORENSICS ACTIVE"));
  display.drawLine(0, 9, 127, 9, SSD1306_WHITE);

  // Threat being analyzed
  display.setCursor(0, 13);
  display.print(F("Target: "));
  char shortType[17]; strncpy(shortType, type, 16); shortType[16] = '\0';
  display.println(shortType);

  // Animated progress bar
  unsigned long elapsed = millis() - monitoring_start_ms;
  int progress = min(100, (int)(elapsed / 60));  // Fills in ~6 seconds
  display.setCursor(0, 26); display.println(F("Llama 3.2 Analysis:"));
  display.drawRect(4, 36, 120, 10, SSD1306_WHITE);
  int fillW = (int)((long)progress * 116 / 100);
  if (fillW > 0) display.fillRect(6, 38, fillW, 6, SSD1306_WHITE);
  char pct[6]; snprintf(pct, sizeof(pct), "%d%%", progress);
  display.setCursor(100, 26); display.print(pct);

  // Status lines
  display.setCursor(0, 49); display.println(F("LangGraph: RUNNING"));
  display.setCursor(0, 58); display.println(F("Playbook:  GENERATING"));

  display.display();
}

// ── OLED Update Dispatcher (called from loop)
void updateOLED() {
  if (!hw_oled_ok) return;
  unsigned long now = millis();
  if (now - last_oled_update_ms < 250) return;  // 4 FPS for smooth animations
  last_oled_update_ms = now;
  oled_blink = !oled_blink;

  portENTER_CRITICAL(&cntMux);
  int snap = cnt_total;
  portEXIT_CRITICAL(&cntMux);
  int approxRate = snap / max(1UL, (millis() - last_telemetry_ms) / 1000 + 1);
  int rssi = (WiFi.status() == WL_CONNECTED) ? WiFi.RSSI() : -99;

  switch (sysState) {
    case ST_SAFE:
      oledSafe(approxRate, rssi);
      break;
    case ST_ALERT:
      oledAlert(g_alert_type, g_alert_mac, g_alert_rssi, g_alert_ch, g_alert_pkts, oled_blink);
      break;
    case ST_MONITORING:
      oledMonitoring(g_alert_type);
      break;
    default:
      break;
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   SPEAKER — MAX98357A I2S AUDIO
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
bool initSpeaker() {
  i2s_config_t cfg = {
    .mode                 = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX),
    .sample_rate          = 16000,
    .bits_per_sample      = I2S_BITS_PER_SAMPLE_16BIT,
    .channel_format       = I2S_CHANNEL_FMT_ONLY_LEFT,
    .communication_format = I2S_COMM_FORMAT_STAND_I2S,
    .intr_alloc_flags     = 0,
    .dma_buf_count        = 8,
    .dma_buf_len          = 256,
    .use_apll             = false,
    .fixed_mclk           = 0
  };
  i2s_pin_config_t pins = {
    .bck_io_num   = SPK_BCK,
    .ws_io_num    = SPK_WS,
    .data_out_num = SPK_DATA,
    .data_in_num  = I2S_PIN_NO_CHANGE
  };
  if (i2s_driver_install(SPK_I2S_PORT, &cfg, 0, NULL) != ESP_OK) return false;
  if (i2s_set_pin(SPK_I2S_PORT, &pins) != ESP_OK) return false;
  i2s_zero_dma_buffer(SPK_I2S_PORT);
  Serial.println("[SPK] MAX98357A I2S initialized OK");
  return true;
}

void spkTone(int freqHz, int durationMs) {
  int sampleRate = 16000;
  int n = (sampleRate * durationMs) / 1000;
  int16_t* buf = (int16_t*)malloc(n * sizeof(int16_t));
  if (!buf) return;
  if (freqHz > 0) {
    for (int i = 0; i < n; i++) {
      float t = (float)i / (float)sampleRate;
      buf[i] = (int16_t)(7000.0f * sinf(2.0f * M_PI * freqHz * t));
    }
  } else {
    memset(buf, 0, n * sizeof(int16_t));
  }
  size_t written;
  i2s_write(SPK_I2S_PORT, buf, n * sizeof(int16_t), &written, pdMS_TO_TICKS(durationMs + 200));
  free(buf);
}

// Combined Buzzer + Speaker alarm for maximum impact
void playAlertAlarm() {
  Serial.println("[AUDIO] !! THREAT ALARM !!");
  for (int i = 0; i < 3; i++) {
    tone(BUZZER_PIN, 2500, 100);   // Buzzer: piercing high pitch
    if (hw_spk_ok) spkTone(1800, 100); // Speaker: digital siren
    noTone(BUZZER_PIN);
    delay(40);
    tone(BUZZER_PIN, 3000, 80);
    if (hw_spk_ok) spkTone(2200, 80);
    noTone(BUZZER_PIN);
    delay(30);
  }
}

void playAllClear() {
  Serial.println("[AUDIO] Threat contained — All Clear");
  buzzerAllClear();
  if (hw_spk_ok) {
    spkTone(784, 90); spkTone(0, 30);
    spkTone(659, 90); spkTone(0, 30);
    spkTone(523, 160);
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   MICROPHONE — INMP441 I2S
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
bool initMic() {
  i2s_config_t cfg = {
    .mode                 = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX),
    .sample_rate          = 16000,
    .bits_per_sample      = I2S_BITS_PER_SAMPLE_32BIT,
    .channel_format       = I2S_CHANNEL_FMT_ONLY_LEFT,
    .communication_format = I2S_COMM_FORMAT_STAND_I2S,
    .intr_alloc_flags     = 0,
    .dma_buf_count        = 4,
    .dma_buf_len          = 128,
    .use_apll             = false,
    .fixed_mclk           = 0
  };
  i2s_pin_config_t pins = {
    .bck_io_num   = MIC_BCK,
    .ws_io_num    = MIC_WS,
    .data_out_num = I2S_PIN_NO_CHANGE,
    .data_in_num  = MIC_DATA
  };
  if (i2s_driver_install(MIC_I2S_PORT, &cfg, 0, NULL) != ESP_OK) return false;
  if (i2s_set_pin(MIC_I2S_PORT, &pins) != ESP_OK) return false;
  Serial.println("[MIC] INMP441 I2S initialized OK");
  return true;
}

void audioTask(void* pvParams) {
  int32_t rawBuf[128];
  size_t bytesRead;
  bool voiceActive = false;
  unsigned long voiceStart = 0;

  while (true) {
    esp_err_t r = i2s_read(MIC_I2S_PORT, rawBuf, sizeof(rawBuf), &bytesRead, pdMS_TO_TICKS(100));
    if (r != ESP_OK || bytesRead == 0) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }

    int n = bytesRead / sizeof(int32_t);
    int64_t sumSq = 0;
    for (int i = 0; i < n; i++) {
      int32_t s = rawBuf[i] >> 8;
      sumSq += (int64_t)s * s;
    }
    int32_t rms = (n > 0) ? (int32_t)sqrtf((float)sumSq / n) : 0;

    if (rms > VOICE_THRESHOLD) {
      if (!voiceActive) { voiceActive = true; voiceStart = millis(); }
      else if (millis() - voiceStart >= VOICE_HOLD_MS) {
        if (!voice_trigger) {
          voice_trigger = true;
          Serial.printf("[MIC] Voice trigger! RMS=%d\n", rms);
        }
        voiceActive = false;
      }
    } else { voiceActive = false; }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   CORE 0: PROMISCUOUS SNIFFER (ISR)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
void IRAM_ATTR sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t pkt_type) {
  if (pkt_type == WIFI_PKT_MISC) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  mac_hdr_t* hdr = (mac_hdr_t*)pkt->payload;
  int8_t rssi = pkt->rx_ctrl.rssi;

  uint8_t ftype = (hdr->frame_ctrl >> 2) & 0x03;
  uint8_t fsubtype = (hdr->frame_ctrl >> 4) & 0x0F;

  portENTER_CRITICAL_ISR(&cntMux);
  cnt_total++;
  if (ftype == 0x00) cnt_mgmt++;
  else if (ftype == 0x02) cnt_data++;
  portEXIT_CRITICAL_ISR(&cntMux);

  // Deauth detection (0x00 type, 0x0C subtype)
  if (ftype == 0x00 && fsubtype == 0x0C) {
    portENTER_CRITICAL_ISR(&cntMux);
    cnt_deauth++;
    int snap = cnt_deauth;
    portEXIT_CRITICAL_ISR(&cntMux);

    if (snap >= DEAUTH_THRESHOLD) {
      ThreatAlert a; strlcpy(a.type, "DEAUTH_FLOOD", sizeof(a.type));
      fmtMAC(hdr->addr2, a.mac); a.rssi = rssi; a.channel = current_channel; a.count = snap;
      BaseType_t woken = pdFALSE; xQueueSendFromISR(alertQueue, &a, &woken);
      portENTER_CRITICAL_ISR(&cntMux); cnt_deauth = 0; portEXIT_CRITICAL_ISR(&cntMux);
    }
  }

  // Probe flood detection (0x00 type, 0x04 subtype)
  if (ftype == 0x00 && fsubtype == 0x04) {
    portENTER_CRITICAL_ISR(&cntMux);
    cnt_probe++;
    int snap = cnt_probe;
    portEXIT_CRITICAL_ISR(&cntMux);

    if (snap >= PROBE_THRESHOLD) {
      ThreatAlert a; strlcpy(a.type, "PROBE_FLOOD", sizeof(a.type));
      fmtMAC(hdr->addr2, a.mac); a.rssi = rssi; a.channel = current_channel; a.count = snap;
      BaseType_t woken = pdFALSE; xQueueSendFromISR(alertQueue, &a, &woken);
      portENTER_CRITICAL_ISR(&cntMux); cnt_probe = 0; portEXIT_CRITICAL_ISR(&cntMux);
    }
  }
}

void snifferTask(void* pvParams) {
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_channel(HOME_CHANNEL, WIFI_SECOND_CHAN_NONE);
  while (true) { vTaskDelay(pdMS_TO_TICKS(1000)); }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   WEBSOCKET — FULL BIDIRECTIONAL HANDLER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
void enterAlertState(const char* type, const char* mac, int8_t rssi, uint8_t ch, int pkts) {
  sysState = ST_ALERT;
  alert_start_ms = millis();
  strlcpy(g_alert_type, type, sizeof(g_alert_type));
  strlcpy(g_alert_mac, mac, sizeof(g_alert_mac));
  g_alert_rssi = rssi;
  g_alert_ch   = ch;
  g_alert_pkts = pkts;

  Serial.printf("[ALERT] %s from %s CH:%d RSSI:%d PKT:%d\n", type, mac, ch, rssi, pkts);

  // Immediate visual + audio feedback
  if (hw_oled_ok) oledAlert(type, mac, rssi, ch, pkts, true);
  playAlertAlarm();
}

void enterMonitoringState(const char* type) {
  sysState = ST_MONITORING;
  monitoring_start_ms = millis();
  strlcpy(g_alert_type, type, sizeof(g_alert_type));

  Serial.printf("[MONITORING] AI analyzing: %s\n", type);

  playAllClear();
  if (hw_oled_ok) oledMonitoring(type);
}

void wsEvent(WStype_t type, uint8_t* payload, size_t length) {
  if (type == WStype_CONNECTED) {
    ws_connected = true;
    Serial.println("[WS] Connected to FastAPI backend");
    webSocket.sendTXT("{\"event\":\"sentinel_online\",\"version\":\"4.1\"}");
    buzzerWsConnect();
  }
  else if (type == WStype_DISCONNECTED) {
    ws_connected = false;
    Serial.println("[WS] Disconnected from backend");
    buzzerWsDisconnect();
  }
  else if (type == WStype_TEXT) {
    StaticJsonDocument<512> doc;
    if (deserializeJson(doc, payload, length) != DeserializationError::Ok) return;

    const char* msgType = doc["type"] | "";

    // ── Backend sends simulate_alert when UI triggers attack simulation
    if (strcmp(msgType, "simulate_alert") == 0) {
      const char* ttype = doc["threat_type"] | "SIMULATED_ATTACK";
      const char* mac   = doc["mac"] | "FF:FF:FF:FF:FF:FF";
      int8_t  rssi = doc["rssi"] | -42;
      uint8_t ch   = doc["channel"] | 6;
      int     pkts = doc["packet_count"] | 1850;
      enterAlertState(ttype, mac, rssi, ch, pkts);
    }
    // ── Backend sends ai_report when LangGraph analysis is complete
    else if (strcmp(msgType, "ai_report") == 0) {
      const char* ttype = doc["threat_type"] | g_alert_type;
      enterMonitoringState(ttype);
    }
    // ── Backend sends incident_reset to clear all indicators
    else if (strcmp(msgType, "incident_reset") == 0) {
      sysState = ST_SAFE;
      display.invertDisplay(false);
      buzzerTone(500, 100);
      Serial.println("[SYSTEM] Incident cleared — returning to SAFE");
    }
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   TELEMETRY — Send packet stats to backend
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
void sendThreatAlert(ThreatAlert& a) {
  enterAlertState(a.type, a.mac, a.rssi, a.channel, a.count);

  StaticJsonDocument<384> doc;
  doc["event"] = "threat_detected";
  doc["type"]  = a.type;
  doc["mac"]   = a.mac;
  doc["rssi"]  = a.rssi;
  doc["channel"] = a.channel;
  doc["count"]   = a.count;
  doc["timestamp"] = millis();

  String json; serializeJson(doc, json);
  if (ws_connected) webSocket.sendTXT(json);
}

void sendTelemetry() {
  portENTER_CRITICAL(&cntMux);
  int snapTotal = cnt_total; int snapMgmt = cnt_mgmt; int snapData = cnt_data;
  cnt_total = 0; cnt_mgmt = 0; cnt_data = 0;
  portEXIT_CRITICAL(&cntMux);

  int pktPerSec = snapTotal / (TELEMETRY_MS / 1000);

  // DoS flood detection
  if (pktPerSec > DOS_PKT_THRESHOLD) {
    ThreatAlert a; strlcpy(a.type, "DOS_FLOOD", sizeof(a.type));
    strlcpy(a.mac, "FF:FF:FF:FF:FF:FF", sizeof(a.mac));
    a.rssi = WiFi.RSSI(); a.channel = current_channel; a.count = pktPerSec;
    xQueueSend(alertQueue, &a, 0);
  }

  StaticJsonDocument<256> doc;
  doc["event"] = "telemetry";
  doc["pkt_rate"] = pktPerSec;
  doc["mgmt_frames"] = snapMgmt;
  doc["data_frames"] = snapData;
  doc["channel"] = current_channel;
  doc["wifi_rssi"] = WiFi.RSSI();
  doc["timestamp"] = millis();

  String json; serializeJson(doc, json);
  if (ws_connected) webSocket.sendTXT(json);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   SETUP & LOOP
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
void setup() {
  Serial.begin(115200);
  Serial.println("\n[SYSTEM] Sentinel v4.1 (PRO) booting...");

  // 1. Init Buzzer
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  // 2. Init RGB
  pixels.begin();
  pixels.setBrightness(80);
  setRGB(0, 0, 100); // Boot blue

  // 3. Init OLED
  hw_oled_ok = initOLED();
  if (hw_oled_ok) oledBoot(10, "Hardware Init...");
  buzzerTone(800, 60); // Quick boot tick

  // 4. Init Audio
  alertQueue = xQueueCreate(10, sizeof(ThreatAlert));
  hw_spk_ok = initSpeaker();
  hw_mic_ok = initMic();
  if (hw_oled_ok) oledBoot(35, "Audio Subsystem OK");
  buzzerTone(1000, 60);

  // 5. WiFi Connect
  if (hw_oled_ok) oledBoot(45, "Connecting WiFi...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  int wifiRetry = 0;
  while (WiFi.status() != WL_CONNECTED && wifiRetry < 40) {
    delay(500);
    wifiRetry++;
    if (hw_oled_ok && wifiRetry % 3 == 0) {
      int prog = 45 + (wifiRetry * 30 / 40);
      oledBoot(min(75, prog), "Connecting WiFi...");
    }
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[WIFI] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
    if (hw_oled_ok) oledBoot(80, "WiFi Connected!");
    buzzerTone(1200, 60);
  } else {
    Serial.println("[WIFI] Connection failed — continuing offline");
    if (hw_oled_ok) oledBoot(80, "WiFi FAILED - Offline");
    buzzerTone(400, 200);
  }

  // 6. WebSocket
  webSocket.begin(WS_HOST, WS_PORT, WS_PATH);
  webSocket.onEvent(wsEvent);
  webSocket.setReconnectInterval(5000);
  if (hw_oled_ok) oledBoot(90, "WebSocket Init...");

  // 7. Start sniffer on Core 0
  xTaskCreatePinnedToCore(snifferTask, "Sniffer", 16384, NULL, 1, NULL, 0);
  if (hw_mic_ok) xTaskCreate(audioTask, "AudioTask", 8192, NULL, 2, NULL);

  // 8. Boot complete
  if (hw_oled_ok) oledBoot(100, "SYSTEM ONLINE");
  buzzerBootChime();
  delay(500);

  sysState = ST_SAFE;
  setRGB(0, 50, 0);
  Serial.println("[SYSTEM] ===== Sentinel v4.1 (PRO) ONLINE =====");
}

void loop() {
  webSocket.loop();
  updateRGB();

  // Process threat queue from sniffer ISR
  ThreatAlert alert;
  while (xQueueReceive(alertQueue, &alert, 0) == pdTRUE) {
    sendThreatAlert(alert);
  }

  // Voice command trigger
  if (voice_trigger) {
    voice_trigger = false;
    setRGB(255, 0, 255); // Purple flash
    buzzerVoiceAck();
    Serial.println("[VOICE] Command detected — notifying backend");
    if (ws_connected) {
      webSocket.sendTXT("{\"event\":\"voice_command\"}");
    }
  }

  // Periodic telemetry
  if (millis() - last_telemetry_ms >= TELEMETRY_MS) {
    sendTelemetry();
    last_telemetry_ms = millis();

    // Auto-transition: ALERT → MONITORING after telemetry cycle
    if (sysState == ST_ALERT && (millis() - alert_start_ms > 4000)) {
      enterMonitoringState(g_alert_type);
    }
  }

  // Auto-transition: MONITORING → SAFE after 8 seconds
  if (sysState == ST_MONITORING && (millis() - monitoring_start_ms > 8000)) {
    sysState = ST_SAFE;
    display.invertDisplay(false);
    Serial.println("[SYSTEM] Monitoring complete → SAFE");
  }

  // Detection window reset
  if (millis() - last_window_ms >= DETECTION_WINDOW_MS) {
    portENTER_CRITICAL(&cntMux);
    cnt_deauth = 0; cnt_probe = 0;
    portEXIT_CRITICAL(&cntMux);
    last_window_ms = millis();
  }

  updateOLED();
  yield();
}