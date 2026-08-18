import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart as ReBarChart, Bar
} from 'recharts';
import {
  Shield, Server, Cpu, Wifi, Bell, Search,
  Settings, LayoutDashboard, AlertTriangle, TrendingUp,
  TrendingDown, Database, BarChart3, ChevronRight, RefreshCw,
  MemoryStick, Radio, ShieldAlert, Zap, WifiOff, Activity,
  Code, Play, Send, Bot, Download,
  Power, Usb, Volume2, Sparkles
} from 'lucide-react';
import './index.css';

// ─── Configuration ───────────────────────────────────────────────
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';
const WS_TOKEN = import.meta.env.VITE_WS_TOKEN || 'sentinel-dev-token-change-me';

const DEFAULT_DEVICES = [
  { id: 1, mac: "A4:C3:F0:12:34:56", ip: "10.0.1.101", name: "MacBook Pro M3",   vendor: "Apple Inc.",    trusted: true,  sig: -48, rx: 0.72, ry: 0.27 },
  { id: 2, mac: "D8:BB:C1:98:76:54", ip: "10.0.1.102", name: "Samsung 8K QLED",  vendor: "Samsung Elec.", trusted: true,  sig: -61, rx: 0.22, ry: 0.72 },
  { id: 3, mac: "FC:EC:DA:55:44:33", ip: "10.0.1.103", name: "iPhone 15 Pro Max",vendor: "Apple Inc.",    trusted: true,  sig: -44, rx: 0.80, ry: 0.70 },
  { id: 4, mac: "B0:A7:B9:11:22:33", ip: "10.0.1.1",   name: "Sentinel Core AP", vendor: "Cisco Meraki",  trusted: true,  sig: -18, rx: 0.50, ry: 0.50 },
  { id: 5, mac: "C4:E9:84:77:AA:BB", ip: "10.0.1.110", name: "Raspberry Pi 5",   vendor: "Raspberry Pi",  trusted: true,  sig: -53, rx: 0.22, ry: 0.28 },
];

const ATTACK_PRESETS = [
  {
    id: 'DEAUTH_STORM',
    name: '0x0C Deauth Storm',
    desc: 'High-velocity deauthentication frames severing client association.',
    mac: 'DE:AD:BE:EF:00:01',
    channel: 6,
    rssi: -42,
    rate: 1850,
    icon: WifiOff,
    color: '#ff4757'
  },
  {
    id: 'EVIL_TWIN',
    name: 'Evil Twin Rogue AP',
    desc: 'Spoofed Beacon & BSSID cloning network to harvest credentials.',
    mac: 'E0:5A:1B:99:33:AA',
    channel: 6,
    rssi: -35,
    rate: 920,
    icon: ShieldAlert,
    color: '#ff6b81'
  },
  {
    id: 'BEACON_FLOOD',
    name: '0x08 Beacon Saturation',
    desc: 'Broadcasts thousands of fake SSIDs to exhaust wireless stacks.',
    mac: 'AA:11:BB:22:CC:33',
    channel: 1,
    rssi: -48,
    rate: 3200,
    icon: Radio,
    color: '#ff9f43'
  },
  {
    id: 'PROBE_STORM',
    name: '0x04 Probe Recon Burst',
    desc: 'Aggressive probe requests mapping wireless station fingerprints.',
    mac: '8C:3B:AD:77:88:99',
    channel: 11,
    rssi: -58,
    rate: 640,
    icon: Zap,
    color: '#4cc9f0'
  },
  {
    id: 'KARMA_ATTACK',
    name: 'KARMA PNL Hijack',
    desc: 'Responds affirmatively to all SSID requests to coerce connection.',
    mac: 'FA:88:22:CC:55:11',
    channel: 6,
    rssi: -40,
    rate: 810,
    icon: AlertTriangle,
    color: '#7b61ff'
  },
  {
    id: 'PMKID_CAPTURE',
    name: 'PMKID Hash Sniff',
    desc: 'EAPOL frame 1 RSN IE interception for offline password cracking.',
    mac: 'B4:EE:2B:10:99:44',
    channel: 6,
    rssi: -50,
    rate: 450,
    icon: Activity,
    color: '#06d6a0'
  }
];

const FIRMWARE = [
  { title: "Core 0 — Promiscuous Sniffer Task", code: `// main.cpp  (ESP-IDF v5.1 — Dual-Core Architecture)\nvoid setup() {\n  // Pin high-speed RF sniffer exclusively to Core 0\n  xTaskCreatePinnedToCore(\n    snifferTask, "NetSniffer",\n    8192, NULL, 5,\n    &snifferHandle, 0   // ← CORE 0 (Zero frame drops)\n  );\n  \n  // OLED UI + Voice / Telemetry on Core 1\n  xTaskCreatePinnedToCore(\n    voiceDisplayTask, "VoiceUI",\n    4096, NULL, 3, NULL, 1  // ← CORE 1 (Smooth UI)\n  );\n}\n\nvoid snifferTask(void* pvParams) {\n  esp_wifi_set_promiscuous(true);\n  esp_wifi_set_promiscuous_rx_cb(&packetCallback);\n  vTaskDelete(NULL);  // Runs via hardware interrupt\n}` },
  { title: "802.11 Frame Header Parser", code: `// sniffer.cpp — Real-time header classification\nvoid IRAM_ATTR packetCallback(\n  void* buf,\n  wifi_promiscuous_pkt_type_t type\n) {\n  auto* pkt = (wifi_promiscuous_pkt_t*)buf;\n  auto* hdr = (wifi_80211_hdr_t*)pkt->payload;\n\n  uint8_t ftype    = (hdr->frame_ctrl >> 2) & 0x03;\n  uint8_t fsubtype = (hdr->frame_ctrl >> 4) & 0x0F;\n\n  pktPerSecond++;\n  macTracker.record(hdr->addr2);\n\n  // Detect Management Deauth (subtype 0x0C)\n  if (ftype == 0x00 && fsubtype == 0x0C) {\n    if (++deauthCount > DEAUTH_THRESHOLD)\n      xQueueSend(alertQueue, hdr->addr2, 0);\n  }\n}` },
  { title: "WebSocket JSON Dispatcher", code: `// dispatcher.cpp — Async transport to FastAPI backend\nvoid dispatchThreat(ThreatType t, uint8_t* mac) {\n  StaticJsonDocument<256> doc;\n  doc["type"]     = threatTypeStr(t);\n  doc["mac"]      = macToStr(mac);\n  doc["pkt_rate"] = pktPerSecond;\n  doc["channel"]  = currentChannel;\n  doc["rssi"]     = lastRSSI;\n  doc["ts"]       = esp_timer_get_time() / 1000;\n  \n  String payload;\n  serializeJson(doc, payload);\n\n  wsClient.sendTXT(payload);  // → FastAPI WebSocket\n\n  oled.clearDisplay();\n  oled.setTextSize(2);  oled.println("!! ALERT !!");\n  oled.setTextSize(1);  oled.println(threatTypeStr(t));\n  oled.display();\n  setLED(255, 0, 0);    // RGB LED → Red Strobe\n}` },
];

const SERVERS = [
  { id: 1, name: 'prod-web-01', ip: '10.0.1.15', status: 'online', cpu: 67, mem: 72 },
  { id: 2, name: 'prod-api-02', ip: '10.0.1.22', status: 'online', cpu: 45, mem: 58 },
  { id: 3, name: 'prod-db-01', ip: '10.0.2.10', status: 'warning', cpu: 89, mem: 91 },
  { id: 4, name: 'staging-web-01', ip: '10.0.3.5', status: 'online', cpu: 23, mem: 41 },
  { id: 5, name: 'prod-cache-01', ip: '10.0.1.30', status: 'offline', cpu: 0, mem: 0 },
];

function generateCpuHistory() {
  const now = Date.now();
  return Array.from({ length: 24 }, (_, i) => ({
    time: new Date(now - (23 - i) * 3600000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    cpu: Math.round(30 + Math.random() * 40 + Math.sin(i / 3) * 15),
    memory: Math.round(50 + Math.random() * 20 + Math.cos(i / 4) * 10),
    network: Math.round(20 + Math.random() * 50),
  }));
}

function generateNetworkData() {
  return Array.from({ length: 12 }, (_, i) => ({
    time: `${String(i * 2).padStart(2, '0')}:00`,
    inbound: Math.round(100 + Math.random() * 400),
    outbound: Math.round(80 + Math.random() * 300),
  }));
}

function generateUptimeSegments() {
  return Array.from({ length: 30 }, () => {
    const r = Math.random();
    return r > 0.94 ? 'down' : r > 0.88 ? 'degraded' : 'up';
  });
}

function getThreatIcon(type) {
  switch (type) {
    case 'DEAUTH_STORM': return WifiOff;
    case 'EVIL_TWIN': return ShieldAlert;
    case 'BEACON_FLOOD': return Radio;
    case 'PROBE_STORM': return Zap;
    case 'KARMA_ATTACK': return AlertTriangle;
    case 'PMKID_CAPTURE': return Activity;
    default: return AlertTriangle;
  }
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="custom-tooltip">
      <div className="label">{label}</div>
      {payload.map((entry, i) => (
        <div key={i} className="value" style={{ color: entry.color }}>
          {entry.name}: {entry.value}{entry.name === 'network' || entry.name === 'inbound' || entry.name === 'outbound' ? ' MB/s' : '%'}
        </div>
      ))}
    </div>
  );
}

function Gauge({ value, label, color, size = 120 }) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;

  return (
    <div className="gauge-item">
      <svg className="gauge-svg" viewBox="0 0 120 120" style={{ width: size, height: size }}>
        <circle className="gauge-track" cx="60" cy="60" r={radius} />
        <circle
          className="gauge-fill"
          cx="60" cy="60" r={radius}
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
        <text x="60" y="56" textAnchor="middle" fill="var(--text-primary)" fontSize="22" fontWeight="800" fontFamily="Inter">
          {value}
        </text>
        <text x="60" y="72" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="500" fontFamily="Inter">
          %
        </text>
      </svg>
      <div className="gauge-label">{label}</div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, trend, trendDir, colorClass }) {
  return (
    <div className={`stat-card ${colorClass} animate-in`}>
      <div className="stat-card-header">
        <div className={`stat-icon ${colorClass}`}>
          <Icon />
        </div>
        <div className={`stat-trend ${trendDir}`}>
          {trendDir === 'up' ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
          {trend}
        </div>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function ThreatFeedItem({ threat }) {
  const ttype = threat.threat_type || threat.threat || 'ANOMALY';
  const Icon = getThreatIcon(ttype);
  const severity = ttype.includes('DEAUTH') || ttype.includes('TWIN') || ttype.includes('PMKID') ? 'critical' : 'warning';
  const time = threat.received_at
    ? new Date(threat.received_at).toLocaleTimeString()
    : threat.analyzed_at
      ? new Date(threat.analyzed_at).toLocaleTimeString()
      : 'just now';

  return (
    <div className={`alert-item threat-feed-item ${severity}`} id={`threat-${ttype}-${Date.now()}`}>
      <div className={`alert-dot ${severity}`} />
      <div className="alert-content">
        <div className="alert-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon size={14} />
          {threat.type === 'ai_report' ? '🤖 LangGraph AI Forensic Report' : '⚡ Live RF Alert'}: {ttype}
        </div>
        <div className="alert-desc">
          {threat.type === 'ai_report'
            ? threat.analysis
            : threat.data
              ? `Attacker: ${threat.data.attacker_mac || 'N/A'} | Target: ${threat.data.target_mac || 'Broadcast'} | Ch: ${threat.data.channel || '6'} | RSSI: ${threat.data.rssi || '-45'} dBm | Packets: ${threat.data.packet_count || '1850'}`
              : `Attacker: ${threat.attacker_mac || 'N/A'} | Channel: ${threat.channel || 6} | RSSI: ${threat.rssi || -45} dBm`
          }
        </div>
        {threat.mitigation && (
          <div className="threat-mitigation">
            <strong>DevSecOps Tactical Playbook:</strong>
            <pre style={{ margin: '4px 0 0', fontSize: 11.5, whiteSpace: 'pre-wrap', color: 'var(--accent-green)', opacity: 0.95 }}>
              {threat.mitigation}
            </pre>
          </div>
        )}
      </div>
      <div className="alert-time">{time}</div>
    </div>
  );
}

function TopoMap({ devices, attacker, status }) {
  const W = 460, H = 260, router = devices.find(d => d.id === 4) || devices[0], clients = devices.filter(d => d.id !== 4), green = "#06d6a0";
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} style={{ display: "block" }}>
      <defs>
        <marker id="mG" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3z" fill={green} opacity="0.6"/></marker>
        <marker id="mR" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3z" fill="#ff4757" opacity="0.95"/></marker>
      </defs>
      
      <circle cx={router.rx * W} cy={router.ry * H} r="110" fill="none" stroke="rgba(6, 214, 160, 0.08)" strokeWidth="1" strokeDasharray="4 4"/>
      <circle cx={router.rx * W} cy={router.ry * H} r="65" fill="none" stroke="rgba(6, 214, 160, 0.12)" strokeWidth="1"/>

      {clients.map(d => (
        <line key={d.id} x1={d.rx * W} y1={d.ry * H} x2={router.rx * W} y2={router.ry * H}
          stroke={d.trusted && status === "SAFE" ? green : "#ff4757"} strokeWidth="1.2" opacity="0.5"
          strokeDasharray={status !== "SAFE" ? "5,4" : "none"} markerEnd="url(#mG)"/>
      ))}
      
      <rect x={W * 0.35} y={4} width={W * 0.3} height={20} rx={5} fill="rgba(15, 23, 42, 0.85)" stroke="#334155" strokeWidth="1"/>
      <text x={W * 0.5} y={17} textAnchor="middle" fontSize="9" fill="#8b92a5" fontFamily="var(--font-mono)" fontWeight="600">INTERNET GATEWAY</text>
      <line x1={W * 0.5} y1={24} x2={router.rx * W} y2={router.ry * H - 22} stroke="#334155" strokeWidth="1" strokeDasharray="3,3"/>
      
      {status === "SAFE" && <circle cx={router.rx * W} cy={router.ry * H} r="26" fill="none" stroke={green} strokeWidth="1" opacity="0.4">
        <animate attributeName="r" values="22;42;22" dur="3s" repeatCount="indefinite"/>
        <animate attributeName="opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite"/>
      </circle>}
      
      {attacker && <g>
        <line x1={attacker.x * W} y1={attacker.y * H} x2={router.rx * W} y2={router.ry * H} stroke="#ff4757" strokeWidth="2.4" strokeDasharray="6,3" opacity="0.95" markerEnd="url(#mR)">
          <animate attributeName="stroke-dashoffset" from="0" to="-24" dur="0.3s" repeatCount="indefinite"/>
        </line>
        <circle cx={attacker.x * W} cy={attacker.y * H} r="20" fill="none" stroke="#ff4757" strokeWidth="1.5" opacity="0.8">
          <animate attributeName="r" values="14;36;14" dur="1s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.8;0;0.8" dur="1s" repeatCount="indefinite"/>
        </circle>
      </g>}
      
      {devices.map(d => {
        const isR = d.id === 4;
        return (
          <g key={d.id} style={{ cursor: "pointer" }}>
            <circle cx={d.rx * W} cy={d.ry * H} r={isR ? 22 : 14} fill={isR ? "rgba(6, 214, 160, 0.15)" : d.trusted ? "rgba(15, 23, 42, 0.9)" : "rgba(255, 71, 87, 0.2)"} stroke={isR ? green : d.trusted ? "#475569" : "#ff4757"} strokeWidth={isR ? 2 : 1.2}/>
            <text x={d.rx * W} y={d.ry * H + 4} textAnchor="middle" fontSize="10.5" fill={isR ? green : d.trusted ? "#e8eaf0" : "#ff4757"} fontFamily="var(--font-mono)" fontWeight={isR ? "700" : "500"}>{isR ? "AP" : d.name.slice(0, 3).toUpperCase()}</text>
            <text x={d.rx * W} y={d.ry * H + (isR ? 36 : 28)} textAnchor="middle" fontSize="8.5" fill="#8b92a5" fontFamily="var(--font-mono)" fontWeight="500">{d.name}</text>
            <text x={d.rx * W} y={d.ry * H + (isR ? 46 : 38)} textAnchor="middle" fontSize="7.5" fill="#5c6575" fontFamily="var(--font-mono)">{d.ip}</text>
          </g>
        );
      })}
      
      {attacker && <g>
        <circle cx={attacker.x * W} cy={attacker.y * H} r={16} fill="rgba(255, 71, 87, 0.25)" stroke="#ff4757" strokeWidth="2" strokeDasharray="3,2"/>
        <text x={attacker.x * W} y={attacker.y * H + 4} textAnchor="middle" fontSize="10.5" fill="#ff4757" fontFamily="var(--font-mono)" fontWeight="700">ATK</text>
        <text x={attacker.x * W} y={attacker.y * H + 26} textAnchor="middle" fontSize="8.5" fill="#ff4757" fontFamily="var(--font-mono)" fontWeight="600">ROGUE NODE</text>
        <text x={attacker.x * W} y={attacker.y * H + 36} textAnchor="middle" fontSize="7.5" fill="#ff4757" fontFamily="var(--font-mono)">{attacker.mac?.slice(0, 8)}</text>
      </g>}
    </svg>
  );
}

// ─── WebSocket Hook with Auto-Reconnect ───────────────────────────
function useWebSocket(url) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const fullUrl = `${url}/ws/dashboard?token=${encodeURIComponent(WS_TOKEN)}`;
    let ws;
    try {
      ws = new WebSocket(fullUrl);
    } catch (err) {
      console.warn('[Sentinel WS] Construction error:', err);
      return;
    }

    ws.onopen = () => {
      setIsConnected(true);
      console.log('[Sentinel WS] Connected to backend gateway');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLastMessage(data);
      } catch {
        console.warn('[Sentinel WS] Non-JSON message:', event.data);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    };

    ws.onerror = (error) => {
      console.error('[Sentinel WS] Error:', error);
    };

    wsRef.current = ws;
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { isConnected, lastMessage };
}

// ─── Main App Component ──────────────────────────────────────────
function App() {
  const [activeNav, setActiveNav] = useState('dashboard');
  const [cpuHistory] = useState(generateCpuHistory);
  const [networkData] = useState(generateNetworkData);
  const [uptimeSegments] = useState(generateUptimeSegments);
  const [chartTab, setChartTab] = useState('24h');

  const [liveMetrics, setLiveMetrics] = useState({
    cpu: 48,
    memory: 62,
    disk: 53,
    network: 320,
  });

  const { isConnected, lastMessage } = useWebSocket(WS_URL);
  const [threatFeed, setThreatFeed] = useState([]);
  const [threatCount, setThreatCount] = useState(0);

  // Live Threat States
  const [wifiStatus, setWifiStatus] = useState("SAFE");
  const [pktRate, setPktRate] = useState(183);
  const [activeChannel, setActiveChannel] = useState(6);
  const [attacker, setAttacker] = useState(null);
  const [aiReport, setAiReport] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [firmwareTab, setFirmwareTab] = useState(0);

  // Simulation parameters
  const [selectedPreset, setSelectedPreset] = useState(ATTACK_PRESETS[0]);
  const [simMac, setSimMac] = useState(ATTACK_PRESETS[0].mac);
  const [simChannel, setSimChannel] = useState(6);
  const [simRssi, setSimRssi] = useState(-42);
  const [simPkts, setSimPkts] = useState(1850);
  const [simLoading, setSimLoading] = useState(false);

  // AI Chat states
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    {
      role: 'assistant',
      content: 'Hello! I am Sentinel AI, your DevSecOps SOC Security Analyst. I monitor live 802.11 wireless spectrum telemetry, detect RF anomalies (Deauth, Evil Twin, Beacon Floods), and formulate tactical mitigation playbooks. How can I assist your network defense today?'
    }
  ]);

  // Devices & Hardware state
  const [devicesList, setDevicesList] = useState(DEFAULT_DEVICES);
  const [serialPorts, setSerialPorts] = useState([]);
  const [selectedPort, setSelectedPort] = useState('COM3');
  const [serialConnected, setSerialConnected] = useState(false);
  const [voiceEvent, setVoiceEvent] = useState(null);

  // Clear active incident
  const clearActiveIncident = useCallback(async () => {
    setWifiStatus("SAFE");
    setAttacker(null);
    setPktRate(183);
    setAiReport(null);
    setAiLoading(false);
    try {
      await fetch(`${BACKEND_URL}/api/threats/clear`, { method: 'POST' });
    } catch {
      // Ignore network errors on clear
    }
  }, []);

  // Handle incoming WebSocket messages
  useEffect(() => {
    if (!lastMessage) return;

    if (lastMessage.type === 'raw_alert') {
      const newAlert = {
        ...lastMessage.data,
        type: 'raw_alert',
        received_at: lastMessage.received_at || new Date().toISOString(),
      };
      setThreatFeed(prev => [newAlert, ...prev].slice(0, 100));
      setThreatCount(prev => prev + 1);
      setWifiStatus("ALERT");
      setPktRate(lastMessage.data?.packet_count || lastMessage.data?.pkt_rate || 1850);
      if (lastMessage.data?.channel) setActiveChannel(lastMessage.data.channel);
      setAttacker({ mac: lastMessage.data?.attacker_mac || 'UNKNOWN_ROGUE', x: 0.15, y: 0.45 });
      setAiLoading(true);
      setAiReport(null);
    } else if (lastMessage.type === 'ai_report') {
      const newReport = {
        ...lastMessage,
        received_at: lastMessage.analyzed_at || new Date().toISOString(),
      };
      setThreatFeed(prev => [newReport, ...prev].slice(0, 100));
      setAiLoading(false);
      setAiReport(lastMessage);
      setWifiStatus("MITIGATING / LOGGED");
    } else if (lastMessage.type === 'esp32_voice_event') {
      setVoiceEvent(lastMessage.raw || `${lastMessage.claps} claps → ${lastMessage.command}`);
      setTimeout(() => setVoiceEvent(null), 4000);
    } else if (lastMessage.type === 'incident_reset') {
      clearActiveIncident();
    }
  }, [lastMessage, clearActiveIncident]);

  // Fetch metrics & devices from backend
  const refreshBackendData = useCallback(async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/system/metrics`);
      if (res.ok) {
        const data = await res.json();
        setLiveMetrics(prev => ({
          cpu: data.cpu || prev.cpu,
          memory: data.memory || prev.memory,
          disk: data.disk || prev.disk,
          network: Math.round((data.network_bytes_recv || 1024000) / 1024 / 100),
        }));
      }

      // Fetch serial ports
      const portRes = await fetch(`${BACKEND_URL}/api/serial/ports`);
      if (portRes.ok) {
        const portData = await portRes.json();
        setSerialPorts(portData.ports || []);
        if (portData.ports?.length > 0 && !selectedPort) {
          setSelectedPort(portData.ports[0].device);
        }
        setSerialConnected(portData.bridge_status?.is_running || false);
      }
    } catch {
      // Backend not reached, keep smooth fallback
    }
  }, [selectedPort]);

  useEffect(() => {
    const interval = setInterval(refreshBackendData, 3000);
    refreshBackendData();
    return () => {
      clearInterval(interval);
    };
  }, [refreshBackendData]);

  // Launch Attack Simulation
  const triggerSimulation = async (preset = selectedPreset) => {
    setSimLoading(true);
    try {
      await fetch(`${BACKEND_URL}/api/threats/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_type: preset.id,
          attacker_mac: simMac || preset.mac,
          target_mac: 'FF:FF:FF:FF:FF:FF',
          channel: simChannel || preset.channel,
          rssi: simRssi || preset.rssi,
          packet_count: simPkts || preset.rate
        })
      });
    } catch (e) {
      console.error('Simulation error:', e);
    } finally {
      setSimLoading(false);
    }
  };

  // Send AI Chat Query
  const sendChatMessage = async (queryText = chatInput) => {
    if (!queryText.trim() || chatLoading) return;
    const userMsg = { role: 'user', content: queryText };
    setChatMessages(prev => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const res = await fetch(`${BACKEND_URL}/api/agent/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: queryText,
          context_threat_type: wifiStatus !== 'SAFE' ? (selectedPreset.id) : 'GENERAL_SECURITY',
          chat_history: chatMessages
        })
      });
      const data = await res.json();
      setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (e) {
      setChatMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error connecting to Sentinel AI backend: ${e.message}. Ensure backend is running on ${BACKEND_URL}.`
      }]);
    } finally {
      setChatLoading(false);
    }
  };

  // Toggle Serial Connection
  const toggleSerial = async () => {
    if (serialConnected) {
      await fetch(`${BACKEND_URL}/api/serial/disconnect`, { method: 'POST' });
      setSerialConnected(false);
    } else {
      const res = await fetch(`${BACKEND_URL}/api/serial/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: selectedPort || 'COM3', baud_rate: 115200 })
      });
      if (res.ok) setSerialConnected(true);
    }
  };

  // Toggle Device Trust
  const toggleDeviceTrust = (mac) => {
    setDevicesList(prev => prev.map(d => d.mac === mac ? { ...d, trusted: !d.trusted } : d));
  };

  // Export threats CSV
  const exportCsv = () => {
    window.open(`${BACKEND_URL}/api/threats/export?format=csv`, '_blank');
  };

  return (
    <div className="app-layout">
      {/* ─── Sidebar ─────────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <Shield size={20} />
          </div>
          <div className="sidebar-brand">
            <h1>Sentinel</h1>
            <span>DevSecOps Monitor</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Overview</div>
          {[
            { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
            { id: 'threats', icon: ShieldAlert, label: 'Threats & Sandbox', badge: threatCount > 0 ? String(threatCount) : undefined },
            { id: 'ai-agent', icon: Bot, label: 'AI SOC Analyst', badge: 'AI' },
            { id: 'topology', icon: Radio, label: 'Wi-Fi Topology' },
            { id: 'esp32-hub', icon: Usb, label: 'ESP32 Hardware' },
            { id: 'servers', icon: Server, label: 'Cluster Servers' },
            { id: 'alerts', icon: AlertTriangle, label: 'Alert Logs', badge: String(threatFeed.length) },
            { id: 'metrics', icon: BarChart3, label: 'Metrics Deep-Dive' },
          ].map(item => (
            <div
              key={item.id}
              id={`nav-${item.id}`}
              className={`nav-item ${activeNav === item.id ? 'active' : ''}`}
              onClick={() => setActiveNav(item.id)}
            >
              <item.icon />
              <span>{item.label}</span>
              {item.badge && <span className="badge">{item.badge}</span>}
            </div>
          ))}

          <div className="nav-section-label">Infrastructure</div>
          {[
            { id: 'firmware', icon: Code, label: 'ESP32 Firmware' },
            { id: 'databases', icon: Database, label: 'Vector DB' },
            { id: 'settings', icon: Settings, label: 'Settings' },
          ].map(item => (
            <div
              key={item.id}
              id={`nav-${item.id}`}
              className={`nav-item ${activeNav === item.id ? 'active' : ''}`}
              onClick={() => setActiveNav(item.id)}
            >
              <item.icon />
              <span>{item.label}</span>
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-status">
            <div className={`status-dot ${isConnected ? '' : 'disconnected'}`} />
            <div>
              <span className="status-text">{isConnected ? 'FastAPI Gateway Online' : 'Connecting to Gateway...'}</span>
              <span className="status-sub">
                {isConnected
                  ? `${threatCount} threats processed`
                  : 'Standby mode'
                }
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* ─── Main Content ────────────────────────────────────── */}
      <main className="main-content">
        {/* Top Bar */}
        <header className="topbar">
          <div className="topbar-left">
            <h2>{activeNav.charAt(0).toUpperCase() + activeNav.slice(1).replace('-', ' ')}</h2>
            <span className="breadcrumb">/ DevSecOps & Wi-Fi IDS AI Platform v3.5</span>
          </div>
          <div className="topbar-right">
            {voiceEvent && (
              <div className="live-badge" style={{ background: 'rgba(123, 97, 255, 0.2)', color: '#7b61ff', border: '1px solid #7b61ff' }}>
                <Volume2 size={13} /> {voiceEvent}
              </div>
            )}

            {/* ESP32 Hardware Mirror */}
            <div className={`oled-box ${wifiStatus === "ALERT" ? "alert" : ""}`} style={{ padding: '6px 12px', minWidth: 155 }}>
              <div style={{ fontSize: 7, color: wifiStatus === "ALERT" ? "#f87171" : "#16a34a", letterSpacing: "0.15em", fontWeight: 700 }}>
                ESP32-S3 CORE OLED
              </div>
              <div style={{ fontWeight: 700, color: wifiStatus === "ALERT" ? "#ff4455" : "#4ade80" }}>
                {wifiStatus === "ALERT" ? "!! ATTACK DETECTED !!" : "SENTINEL v3.5 ACTIVE"}
              </div>
              <div style={{ fontSize: 9, color: "#8b92a5" }}>
                PKT/S: {pktRate} | CH:{activeChannel} ({wifiStatus})
              </div>
            </div>

            <div className={`connection-badge ${isConnected ? 'connected' : 'disconnected'}`} id="ws-status">
              <Activity size={12} />
              {isConnected ? 'Live WebSocket' : 'Connecting...'}
            </div>
            
            <button className="topbar-icon-btn" id="btn-refresh" title="Refresh Telemetry" onClick={refreshBackendData}>
              <RefreshCw size={16} />
            </button>
            <button className="topbar-icon-btn" id="btn-ai-quick" title="Ask Sentinel AI" onClick={() => setActiveNav('ai-agent')}>
              <Bot size={16} />
            </button>
            <button className="topbar-icon-btn" id="btn-notifications" title="Notifications" onClick={() => setActiveNav('alerts')}>
              <Bell size={16} />
              {threatCount > 0 && <span className="notification-dot" />}
            </button>
            <div className="topbar-avatar" id="user-avatar" title="SecOps Admin">
              PS
            </div>
          </div>
        </header>

        {/* ─── VIEW 1: DASHBOARD ───────────────────────────────── */}
        {activeNav === 'dashboard' && (
          <div className="dashboard">
            <div className="stats-grid">
              <StatCard
                icon={Cpu}
                label="Host CPU Load"
                value={`${Math.round(liveMetrics.cpu)}%`}
                trend="2.4%"
                trendDir="up"
                colorClass="cyan"
              />
              <StatCard
                icon={MemoryStick}
                label="System Memory"
                value={`${Math.round(liveMetrics.memory)}%`}
                trend="1.2%"
                trendDir="up"
                colorClass="purple"
              />
              <StatCard
                icon={Radio}
                label="802.11 Packet Rate"
                value={`${pktRate} pkt/s`}
                trend={wifiStatus === "ALERT" ? "12× SPIKE" : "Nominal"}
                trendDir={wifiStatus === "ALERT" ? "up" : "down"}
                colorClass={wifiStatus === "ALERT" ? "red" : "green"}
              />
              <StatCard
                icon={Wifi}
                label="Network Throughput"
                value={`${Math.round(liveMetrics.network)} MB/s`}
                trend="12%"
                trendDir="up"
                colorClass="green"
              />
            </div>

            {/* Quick Simulation Bar */}
            <div className="panel animate-in" style={{ border: '1px solid rgba(255, 71, 87, 0.25)', background: 'linear-gradient(180deg, rgba(255, 71, 87, 0.05), rgba(15, 23, 42, 0.7))' }}>
              <div className="panel-header" style={{ marginBottom: 12 }}>
                <div>
                  <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Sparkles size={18} style={{ color: 'var(--accent-red)' }} />
                    Live Threat Injection & Sandbox Triggers
                  </div>
                  <div className="panel-subtitle">Dispatch realistic 802.11 physical attack vectors to trigger real-time LangGraph AI forensic diagnosis</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="panel-tab" onClick={clearActiveIncident} style={{ color: '#06d6a0', borderColor: 'rgba(6, 214, 160, 0.3)' }}>
                    Reset Incident
                  </button>
                  <button className="panel-tab active" onClick={() => setActiveNav('threats')}>
                    Advanced Sandbox <ChevronRight size={14} />
                  </button>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {ATTACK_PRESETS.map(preset => (
                  <button
                    key={preset.id}
                    className="scenario-card"
                    style={{ flex: '1 1 180px', padding: '12px', borderColor: selectedPreset.id === preset.id ? 'var(--accent-red)' : 'var(--border-subtle)' }}
                    onClick={() => {
                      setSelectedPreset(preset);
                      setSimMac(preset.mac);
                      triggerSimulation(preset);
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 700, color: preset.color }}>
                      <preset.icon size={15} /> {preset.name}
                    </div>
                    <div style={{ fontSize: 11, color: '#8b92a5' }}>{preset.rate} pkt/s · CH {preset.channel}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Live Threat Feed Panel */}
            {threatFeed.length > 0 && (
              <div className="panel animate-in threat-panel">
                <div className="panel-header">
                  <div>
                    <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <ShieldAlert size={18} style={{ color: 'var(--accent-red)' }} />
                      Live Threat Telemetry Feed
                    </div>
                    <div className="panel-subtitle">{threatCount} incidents logged from ESP32 Sensor & LangGraph AI</div>
                  </div>
                  <div className="panel-actions">
                    <div className="live-badge threat-live">
                      <span className="live-pulse" />
                      LIVE RF
                    </div>
                    <button className="panel-tab" onClick={() => setActiveNav('threats')}>
                      Inspect All
                    </button>
                  </div>
                </div>
                <div className="alert-list threat-feed-list">
                  {threatFeed.slice(0, 4).map((threat, i) => (
                    <ThreatFeedItem key={`${threat.type}-${i}`} threat={threat} />
                  ))}
                </div>
              </div>
            )}

            {/* Performance Chart + Resource Gauges */}
            <div className="charts-row">
              <div className="panel animate-in">
                <div className="panel-header">
                  <div>
                    <div className="panel-title">System & RF Telemetry Performance</div>
                    <div className="panel-subtitle">CPU, Memory & Network bandwidth over time</div>
                  </div>
                  <div className="panel-actions">
                    <div className="live-badge">Live</div>
                    {['1h', '6h', '24h', '7d'].map(tab => (
                      <button
                        key={tab}
                        className={`panel-tab ${chartTab === tab ? 'active' : ''}`}
                        onClick={() => setChartTab(tab)}
                      >
                        {tab}
                      </button>
                    ))}
                  </div>
                </div>
                <ResponsiveContainer width="100%" height={280}>
                  <AreaChart data={cpuHistory}>
                    <defs>
                      <linearGradient id="gradCpu" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06d6a0" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#06d6a0" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gradMem" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#7b61ff" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#7b61ff" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gradNet" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#4cc9f0" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#4cc9f0" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                    <XAxis dataKey="time" tick={{ fill: '#5c6575', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#5c6575', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="cpu" name="cpu" stroke="#06d6a0" fill="url(#gradCpu)" strokeWidth={2} dot={false} />
                    <Area type="monotone" dataKey="memory" name="memory" stroke="#7b61ff" fill="url(#gradMem)" strokeWidth={2} dot={false} />
                    <Area type="monotone" dataKey="network" name="network" stroke="#4cc9f0" fill="url(#gradNet)" strokeWidth={1.5} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="panel animate-in">
                <div className="panel-header">
                  <div>
                    <div className="panel-title">Resource Utilization</div>
                    <div className="panel-subtitle">Node health overview</div>
                  </div>
                </div>
                <div className="gauges-grid">
                  <Gauge value={Math.round(liveMetrics.cpu)} label="CPU" color="var(--accent-cyan)" />
                  <Gauge value={Math.round(liveMetrics.memory)} label="Memory" color="var(--accent-purple)" />
                  <Gauge value={Math.round(liveMetrics.disk)} label="Disk" color="var(--accent-orange)" />
                  <Gauge value={Math.round(liveMetrics.network / 5)} label="Network" color="var(--accent-blue)" />
                </div>
              </div>
            </div>

            {/* 30-Day Uptime Bar */}
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Uptime — Last 30 Days</div>
                  <div className="panel-subtitle">99.8% operational availability across DevSecOps nodes</div>
                </div>
                <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--text-muted)' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--accent-green)', display: 'inline-block' }} /> Operational
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--accent-orange)', display: 'inline-block' }} /> Degraded
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--accent-red)', display: 'inline-block' }} /> Downtime
                  </span>
                </div>
              </div>
              <div className="uptime-bar-container">
                {uptimeSegments.map((seg, i) => (
                  <div
                    key={i}
                    className={`uptime-segment ${seg}`}
                    style={{ height: seg === 'up' ? '100%' : seg === 'degraded' ? '70%' : '40%' }}
                    title={`Day ${i + 1}: ${seg}`}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 2: THREATS & SANDBOX ───────────────────────── */}
        {activeNav === 'threats' && (
          <div className="dashboard">
            <div className="charts-row">
              {/* Left Column: Attack Sandbox */}
              <div className="panel animate-in" style={{ display: 'flex', flexDirection: 'column' }}>
                <div className="panel-header">
                  <div>
                    <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Radio size={18} style={{ color: 'var(--accent-red)' }} />
                      802.11 Wi-Fi Threat Injection Console
                    </div>
                    <div className="panel-subtitle">Configure attack parameters or select rapid test presets</div>
                  </div>
                  <div className={`live-badge ${wifiStatus === 'ALERT' ? 'threat-live' : ''}`}>
                    {wifiStatus === 'ALERT' ? 'ATTACK ACTIVE' : 'STANDBY'}
                  </div>
                </div>

                <div className="sim-grid">
                  {ATTACK_PRESETS.map(preset => (
                    <div
                      key={preset.id}
                      className={`sim-card ${selectedPreset.id === preset.id ? 'active' : ''}`}
                      onClick={() => {
                        setSelectedPreset(preset);
                        setSimMac(preset.mac);
                        setSimChannel(preset.channel);
                        setSimRssi(preset.rssi);
                        setSimPkts(preset.rate);
                      }}
                    >
                      <div className="sim-card-title">
                        <preset.icon size={15} style={{ color: preset.color }} />
                        {preset.name}
                      </div>
                      <div className="sim-card-desc">{preset.desc}</div>
                    </div>
                  ))}
                </div>

                <div className="sim-params">
                  <div className="sim-param-item">
                    <label>Attacker MAC Address</label>
                    <input
                      type="text"
                      value={simMac}
                      onChange={(e) => setSimMac(e.target.value)}
                      placeholder="DE:AD:BE:EF:00:01"
                    />
                  </div>
                  <div className="sim-param-item">
                    <label>Target Channel (1 - 14)</label>
                    <input
                      type="number"
                      min="1"
                      max="14"
                      value={simChannel}
                      onChange={(e) => setSimChannel(parseInt(e.target.value) || 6)}
                    />
                  </div>
                  <div className="sim-param-item">
                    <label>Packet Injection Rate (pkt/s)</label>
                    <input
                      type="number"
                      value={simPkts}
                      onChange={(e) => setSimPkts(parseInt(e.target.value) || 1000)}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 10 }}>
                  <button
                    className="btn-launch-attack"
                    style={{ flex: 2 }}
                    onClick={() => triggerSimulation()}
                    disabled={simLoading}
                  >
                    <Play size={16} /> {simLoading ? 'Dispatching...' : `Launch ${selectedPreset.name}`}
                  </button>
                  <button
                    className="panel-tab"
                    style={{ flex: 1, padding: '12px', textAlign: 'center', background: 'rgba(6, 214, 160, 0.1)', color: '#06d6a0', borderColor: 'rgba(6, 214, 160, 0.3)' }}
                    onClick={clearActiveIncident}
                  >
                    Clear Incident
                  </button>
                </div>
              </div>

              {/* Right Column: AI Forensic Deck */}
              <div className="panel animate-in" style={{ display: 'flex', flexDirection: 'column' }}>
                <div className="panel-header">
                  <div>
                    <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Bot size={18} style={{ color: 'var(--accent-cyan)' }} />
                      LangGraph AI Agent Forensic Deck
                    </div>
                    <div className="panel-subtitle">Real-time LLM inference & DevSecOps mitigation playbook</div>
                  </div>
                  <div className="live-badge threat-live">
                    <span className="live-pulse" />
                    AI AGENT ACTIVE
                  </div>
                </div>

                <div style={{ flex: 1, padding: '10px 0', overflowY: 'auto' }}>
                  {aiLoading && (
                    <div style={{ padding: '14px 0' }}>
                      <div style={{ fontSize: 11, color: '#ff9f43', fontWeight: 700, letterSpacing: '0.12em', marginBottom: 14 }}>
                        LANGGRAPH AGENT PROCESSING THREAT PAYLOAD...
                      </div>
                      {[
                        "Ingesting 802.11 management/data frame headers from sniffer",
                        "Querying FAISS vector database for exact threat signatures",
                        "Running live LLM forensic inference on frame characteristics",
                        "Generating actionable DevSecOps tactical mitigation playbook"
                      ].map((step, idx) => (
                        <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', fontSize: 13, color: '#e8eaf0' }}>
                          <span style={{ color: '#06d6a0', fontWeight: 800 }}>✓</span> {step}
                        </div>
                      ))}
                    </div>
                  )}

                  {!aiLoading && !aiReport && (
                    <div style={{ color: '#5c6575', fontSize: 13, padding: '50px 20px', textAlign: 'center' }}>
                      <span style={{ color: '#06d6a0', fontWeight: 'bold', fontSize: 24, display: 'block', marginBottom: 12 }}>📡</span>
                      <strong>Ready for Threat Ingestion</strong><br/>
                      <span style={{ fontSize: 12, marginTop: 6, display: 'inline-block' }}>
                        Click any attack preset on the left or send real frames from your ESP32 hardware to trigger real-time AI security analysis.
                      </span>
                    </div>
                  )}

                  {aiReport && (
                    <div style={{ background: 'rgba(6, 214, 160, 0.05)', border: '1px solid rgba(6, 214, 160, 0.25)', borderRadius: 12, padding: 18 }}>
                      <div style={{ fontSize: 11, color: '#06d6a0', fontWeight: 700, letterSpacing: '0.12em', marginBottom: 10 }}>
                        AI SOC ANALYST FORENSIC REPORT · REAL-TIME INFERENCE
                      </div>
                      <div style={{ fontSize: 13, color: '#e8eaf0', lineHeight: 1.7 }}>
                        <div style={{ marginBottom: 14 }}>
                          <strong style={{ color: '#4cc9f0', display: 'block', marginBottom: 4 }}>Forensic Diagnosis:</strong>
                          <span>{aiReport.analysis}</span>
                        </div>
                        <div>
                          <strong style={{ color: '#06d6a0', display: 'block', marginBottom: 6 }}>Actionable Mitigation Playbook:</strong>
                          <div style={{ background: 'rgba(3, 7, 18, 0.85)', padding: 14, borderRadius: 8, borderLeft: '3px solid #06d6a0', fontFamily: 'var(--font-mono)', fontSize: 12, color: '#4ade80', whiteSpace: 'pre-wrap' }}>
                            {aiReport.mitigation}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Threat Feed History & Export */}
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Threat History & Incident Log</div>
                  <div className="panel-subtitle">{threatFeed.length} recorded events from physical sensor and simulator</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="panel-tab" onClick={exportCsv} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Download size={13} /> Export CSV
                  </button>
                  <button className="panel-tab" onClick={() => setThreatFeed([])}>
                    Clear Feed
                  </button>
                </div>
              </div>

              <div className="alert-list">
                {threatFeed.length === 0 ? (
                  <div style={{ padding: '30px', textAlign: 'center', color: '#5c6575' }}>No active threats logged.</div>
                ) : (
                  threatFeed.map((threat, idx) => (
                    <ThreatFeedItem key={idx} threat={threat} />
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 3: AI SOC ANALYST CHAT ─────────────────────── */}
        {activeNav === 'ai-agent' && (
          <div className="dashboard">
            <div className="panel animate-in" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="panel-header" style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                <div>
                  <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Bot size={20} style={{ color: 'var(--accent-cyan)' }} />
                    Sentinel AI DevSecOps Security Analyst
                  </div>
                  <div className="panel-subtitle">Ask questions about wireless defense, packet forensics, PMF 802.11w, and threat remediation</div>
                </div>
                <div className="live-badge" style={{ background: 'rgba(76, 201, 240, 0.15)', color: 'var(--accent-cyan)' }}>
                  LangGraph + FAISS Engine
                </div>
              </div>

              <div className="ai-chat-container">
                <div className="ai-chat-messages">
                  {chatMessages.map((msg, i) => (
                    <div key={i} className={`chat-bubble ${msg.role}`}>
                      <div className="chat-bubble-header">
                        {msg.role === 'assistant' ? <Bot size={13} /> : <Search size={13} />}
                        {msg.role === 'assistant' ? 'SENTINEL AI ANALYST' : 'SECURITY OPERATOR'}
                      </div>
                      <div style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</div>
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="chat-bubble assistant">
                      <div className="chat-bubble-header">
                        <Bot size={13} /> SENTINEL AI ANALYST
                      </div>
                      <div style={{ color: '#8b92a5' }}>Analyzing security telemetry & consulting vector database...</div>
                    </div>
                  )}
                </div>

                <div className="prompt-chips">
                  {[
                    "How do I protect against Deauth Storms (0x0C)?",
                    "What is 802.11w Protected Management Frames (PMF)?",
                    "Explain Evil Twin Rogue AP detection.",
                    "How does ESP32 Dual-Core architecture prevent packet loss?",
                    "What is PMKID sniffing and how to prevent it?"
                  ].map((chip, idx) => (
                    <button
                      key={idx}
                      className="prompt-chip"
                      onClick={() => sendChatMessage(chip)}
                    >
                      {chip}
                    </button>
                  ))}
                </div>

                <form
                  className="ai-chat-input-box"
                  onSubmit={(e) => {
                    e.preventDefault();
                    sendChatMessage();
                  }}
                >
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder="Ask Sentinel AI about wireless threats, mitigations, or ESP32 architecture..."
                  />
                  <button type="submit" className="ai-chat-send-btn" disabled={!chatInput.trim() || chatLoading}>
                    <Send size={15} /> Send
                  </button>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 4: WI-FI TOPOLOGY RADAR ────────────────────── */}
        {activeNav === 'topology' && (
          <div className="dashboard">
            <div className="topology-grid">
              <div className="panel animate-in">
                <div className="panel-header">
                  <div>
                    <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Radio size={18} style={{ color: 'var(--accent-cyan)' }} />
                      802.11 RF Association Map & Threat Radar
                    </div>
                    <div className="panel-subtitle">Real-time spectrum association and rogue node detection</div>
                  </div>
                  <div className="live-badge">Live RF</div>
                </div>
                <div style={{ padding: '10px 0' }}>
                  <TopoMap devices={devicesList} attacker={attacker} status={wifiStatus} />
                </div>
                <div style={{ display: 'flex', gap: 20, marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border-subtle)' }}>
                  {[{ c: "#06d6a0", l: "Trusted Node" }, { c: "#ff4757", l: "Rogue Transmitter" }, { c: "#5c6575", l: "RF Link" }].map(g => (
                    <div key={g.l} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 10, height: 10, borderRadius: 3, background: g.c }} />
                      <span style={{ fontSize: 12, color: '#8b92a5' }}>{g.l}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel animate-in">
                <div className="panel-header">
                  <div>
                    <div className="panel-title">MAC Whitelist Registry & Access Control</div>
                    <div className="panel-subtitle">{devicesList.length} tracked stations</div>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  {devicesList.map((d, i) => (
                    <div key={i} className="device-row">
                      <div style={{
                        width: 10, height: 10, borderRadius: "50%", flexShrink: 0,
                        background: d.trusted ? "#06d6a0" : "#ff4757",
                        boxShadow: d.trusted ? "0 0 10px rgba(6, 214, 160, 0.6)" : "0 0 10px rgba(255, 71, 87, 0.8)"
                      }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: d.trusted ? "#e8eaf0" : "#ff4757" }}>{d.name}</div>
                        <div style={{ fontSize: 11, color: "#8b92a5", fontFamily: "var(--font-mono)", marginTop: 2 }}>{d.mac} · {d.ip}</div>
                      </div>
                      <div style={{ textAlign: "right", flexShrink: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
                        <button
                          className="panel-tab"
                          style={{
                            padding: '4px 10px',
                            background: d.trusted ? 'rgba(255, 71, 87, 0.1)' : 'rgba(6, 214, 160, 0.1)',
                            color: d.trusted ? '#ff4757' : '#06d6a0',
                            borderColor: d.trusted ? 'rgba(255, 71, 87, 0.3)' : 'rgba(6, 214, 160, 0.3)'
                          }}
                          onClick={() => toggleDeviceTrust(d.mac)}
                        >
                          {d.trusted ? 'Block' : 'Trust'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 5: ESP32 HARDWARE HUB ──────────────────────── */}
        {activeNav === 'esp32-hub' && (
          <div className="dashboard">
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Usb size={18} style={{ color: 'var(--accent-cyan)' }} />
                    ESP32-S3 Serial & WebSocket Hardware Gateway
                  </div>
                  <div className="panel-subtitle">Direct hardware sniffer connection, serial port bridge, and voice commands</div>
                </div>
                <div className={`live-badge ${serialConnected ? 'threat-live' : ''}`}>
                  {serialConnected ? `SERIAL CONNECTED (${selectedPort})` : 'SERIAL DISCONNECTED'}
                </div>
              </div>

              <div className="serial-bridge-box" style={{ marginBottom: 20 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: '#e8eaf0', marginBottom: 4 }}>
                    USB Serial Port Bridge
                  </div>
                  <div style={{ fontSize: 12, color: '#8b92a5' }}>
                    Connect to your plugged-in ESP32 DevKit to stream live 802.11 frames directly into the backend.
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  <select
                    className="serial-select"
                    value={selectedPort}
                    onChange={(e) => setSelectedPort(e.target.value)}
                  >
                    {serialPorts.length > 0 ? (
                      serialPorts.map(p => (
                        <option key={p.device} value={p.device}>{p.device} ({p.description})</option>
                      ))
                    ) : (
                      <>
                        <option value="COM3">COM3 (Default)</option>
                        <option value="COM4">COM4</option>
                        <option value="COM5">COM5</option>
                        <option value="/dev/ttyUSB0">/dev/ttyUSB0 (Linux)</option>
                      </>
                    )}
                  </select>

                  <button
                    className="panel-tab"
                    style={{
                      padding: '10px 18px',
                      background: serialConnected ? 'rgba(255, 71, 87, 0.15)' : 'rgba(6, 214, 160, 0.15)',
                      color: serialConnected ? '#ff4757' : '#06d6a0',
                      borderColor: serialConnected ? '#ff4757' : '#06d6a0'
                    }}
                    onClick={toggleSerial}
                  >
                    <Power size={14} style={{ marginRight: 6 }} />
                    {serialConnected ? 'Disconnect' : 'Connect Port'}
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 16 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-purple)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Volume2 size={16} /> INMP441 Mic Voice Command Map
                  </div>
                  <div style={{ fontSize: 12, color: '#8b92a5', lineHeight: 1.6 }}>
                    • <strong>1 Clap:</strong> Trigger Wi-Fi AP Scan<br/>
                    • <strong>2 Claps:</strong> Stop All Active RF Attacks<br/>
                    • <strong>3 Claps:</strong> Display Hardware Stats on OLED
                  </div>
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 16 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-green)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Cpu size={16} /> Dual-Core FreeRTOS Architecture
                  </div>
                  <div style={{ fontSize: 12, color: '#8b92a5', lineHeight: 1.6 }}>
                    • <strong>Core 0:</strong> Promiscuous 802.11 Sniffer (Interrupt-driven, zero dropped frames)<br/>
                    • <strong>Core 1:</strong> SSD1306 OLED Display + INMP441 Microphone Audio Task
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 6: CLUSTER SERVERS ─────────────────────────── */}
        {activeNav === 'servers' && (
          <div className="dashboard">
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Cluster Infrastructure Servers</div>
                  <div className="panel-subtitle">Real-time health monitoring of production cluster nodes</div>
                </div>
              </div>
              <div className="server-list">
                {SERVERS.map(server => (
                  <div key={server.id} className="server-item" style={{ padding: '16px', borderBottom: '1px solid var(--border-subtle)' }}>
                    <div className={`server-status-indicator ${server.status}`} style={{ width: 12, height: 12 }} />
                    <div className="server-info">
                      <div className="server-name" style={{ fontSize: 15 }}>{server.name}</div>
                      <div className="server-ip" style={{ fontSize: 12 }}>{server.ip} · Status: <span style={{ textTransform: 'uppercase', fontWeight: 600 }}>{server.status}</span></div>
                    </div>
                    <div className="server-metrics" style={{ gap: 32 }}>
                      <div className="server-metric">
                        <div className="server-metric-value" style={{ fontSize: 16 }}>{server.cpu}%</div>
                        <div className="server-metric-label">CPU LOAD</div>
                      </div>
                      <div className="server-metric">
                        <div className="server-metric-value" style={{ fontSize: 16 }}>{server.mem}%</div>
                        <div className="server-metric-label">MEMORY</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 7: ALERTS LOG ──────────────────────────────── */}
        {activeNav === 'alerts' && (
          <div className="dashboard">
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Comprehensive Security & Infrastructure Alert Log</div>
                  <div className="panel-subtitle">All system alerts, SSL notifications, and Wi-Fi IDS triggers</div>
                </div>
                <button className="panel-tab" onClick={() => setThreatFeed([])}>Clear Alerts</button>
              </div>
              <div className="alert-list">
                {threatFeed.length === 0 ? (
                  <div style={{ padding: '30px', textAlign: 'center', color: '#5c6575' }}>No active alerts.</div>
                ) : (
                  threatFeed.map((threat, idx) => (
                    <ThreatFeedItem key={`threat-${idx}`} threat={threat} />
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* ─── VIEW 8: METRICS DEEP-DIVE ───────────────────────── */}
        {activeNav === 'metrics' && (
          <div className="dashboard">
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title">802.11 RF Protocol Frame Composition</div>
                  <div className="panel-subtitle">Management frames vs Data frames real-time breakdown</div>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, padding: '16px 0' }}>
                {[
                  { l: "Data Frames (Type 0x02 — Payload Transport)", v: Math.round(pktRate * 0.93), c: "#06d6a0" },
                  { l: "Management Frames (Type 0x00 — Beacons, Probes, Deauth)", v: Math.round(pktRate * 0.07), c: "#4cc9f0" }
                ].map(f => {
                  const pct = Math.round((f.v / Math.max(pktRate, 1)) * 100);
                  return (
                    <div key={f.l}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 8 }}>
                        <span style={{ color: '#e8eaf0', fontWeight: 600 }}>{f.l}</span>
                        <span style={{ color: f.c, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{pct}% ({f.v} pkt)</span>
                      </div>
                      <div style={{ height: 8, background: 'rgba(255, 255, 255, 0.06)', borderRadius: 4, overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${pct}%`, background: f.c, borderRadius: 4, transition: 'width 0.7s ease' }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Network Throughput & Bandwidth Utilization</div>
                  <div className="panel-subtitle">Inbound vs Outbound traffic breakdown</div>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={260}>
                <ReBarChart data={networkData} barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="time" tick={{ fill: '#5c6575', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#5c6575', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="inbound" name="inbound" fill="#4cc9f0" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="outbound" name="outbound" fill="#7b61ff" radius={[4, 4, 0, 0]} />
                </ReBarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ─── VIEW 9: ESP32 FIRMWARE C++ CODE ─────────────────── */}
        {activeNav === 'firmware' && (
          <div className="dashboard">
            <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
              {FIRMWARE.map((f, i) => (
                <button
                  key={i}
                  className={`fw-tab ${firmwareTab === i ? 'active' : ''}`}
                  onClick={() => setFirmwareTab(i)}
                >
                  {i + 1}. {f.title}
                </button>
              ))}
            </div>
            <div className="panel animate-in">
              <div className="panel-header">
                <div>
                  <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Code size={18} style={{ color: 'var(--accent-green)' }} />
                    {FIRMWARE[firmwareTab].title}
                  </div>
                  <div className="panel-subtitle">ESP-IDF v5.1 Dual-Core C++ / FreeRTOS Task Implementation</div>
                </div>
              </div>
              <pre className="code-view">
                <code>{FIRMWARE[firmwareTab].code}</code>
              </pre>
            </div>
          </div>
        )}

        {/* ─── VIEW 10: SETTINGS / VECTOR DB ───────────────────── */}
        {['settings', 'databases'].includes(activeNav) && (
          <div className="dashboard">
            <div className="panel animate-in" style={{ padding: '40px', textAlign: 'center' }}>
              <Database size={48} style={{ color: 'var(--accent-purple)', margin: '0 auto 16px', opacity: 0.8 }} />
              <div className="panel-title" style={{ fontSize: 18, marginBottom: 8 }}>
                FAISS Vector Database & Threat Signatures
              </div>
              <div className="panel-subtitle" style={{ maxWidth: 540, margin: '0 auto', lineHeight: 1.6 }}>
                The Sentinel FAISS Vector DB indexes 802.11 RFC frame definitions, Deauth attack heuristics, Evil Twin signatures, and DevSecOps playbooks. Live LangGraph pipelines query this vector store with sub-millisecond retrieval latency.
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
