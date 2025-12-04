import React, { useEffect, useMemo, useState } from "react";
import { Line, Doughnut, Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  LineElement,
  PointElement,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import {
  Shield,
  RefreshCcw,
  Wifi,
  Cpu,
  Activity,
  AlertTriangle,
  Play,
  Pause,
} from "lucide-react";
import {
  Routes,
  Route,
  NavLink,
  Navigate,
} from "react-router-dom";

ChartJS.register(
  CategoryScale,
  LinearScale,
  LineElement,
  PointElement,
  ArcElement,
  Tooltip,
  Legend
);

// Backend URL (for development) - will be ignored in frontend-only mode
const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5000";
const FRONTEND_ONLY = true; // Always use frontend-only mode


const MAX_ROWS = 60;
const HISTORY = 30;
const MAX_BACKOFF = 30000;
const MAX_TIMELINE = 12;

function App() {
  // ===== core stats =====
  const [normalCount, setNormalCount] = useState(0);
  const [attackCount, setAttackCount] = useState(0);
  const [quarantineCount, setQuarantineCount] = useState(0);

  const [packets, setPackets] = useState([]);
  const [labels, setLabels] = useState([]);
  const [packetRates, setPacketRates] = useState([]);
  const [byteRates, setByteRates] = useState([]);

  const [protocolCounts, setProtocolCounts] = useState({
    mqtt: 0,
    coap: 0,
    http: 0,
    udp: 0,
  });

  // ===== extra: devices + timeline =====
  const [devices, setDevices] = useState({});
  const [timeline, setTimeline] = useState([]);

  const [toast, setToast] = useState(null);
  const [srvStatus, setSrvStatus] = useState({
    text: "Connecting…",
    color: "#facc15",
  });

  const [intel, setIntel] = useState(null);
  const [reportDate, setReportDate] = useState("–");

  const [esAttempts, setEsAttempts] = useState(0);
  const [isRunning, setIsRunning] = useState(true);
  const [simulationInterval, setSimulationInterval] = useState(null);

  const showToast = (
    msg,
    bg = "linear-gradient(135deg,#ef4444,#fb923c)",
    ttl = 2600
  ) => {
    setToast({ msg, bg });
    setTimeout(() => setToast(null), ttl);
  };

  // ===== handle each incoming packet =====
  const handlePacket = (pkt) => {
    // table
    setPackets((prev) => {
      const updated = [pkt, ...prev];
      return updated.slice(0, MAX_ROWS);
    });

    // charts
    setLabels((prev) => {
      const updated = [
        ...prev,
        pkt.timestamp ?? new Date().toLocaleTimeString(),
      ];
      return updated.slice(-HISTORY);
    });
    setPacketRates((prev) => {
      const updated = [...prev, Number(pkt.packet_rate) || 0];
      return updated.slice(-HISTORY);
    });
    setByteRates((prev) => {
      const updated = [...prev, Number(pkt.byte_rate) || 0];
      return updated.slice(-HISTORY);
    });

    // protocol counts
    setProtocolCounts((prev) => {
      const key = String(pkt.protocol || "unknown").toLowerCase();
      return { ...prev, [key]: (prev[key] || 0) + 1 };
    });

    // stats counters
    if (pkt.label === "Attack") {
      setAttackCount((c) => c + 1);
      showToast(
        `🚨 Attack on ${pkt.device_id}`,
        "linear-gradient(135deg,#ef4444,#fb923c)"
      );

      // threat timeline
      setTimeline((prev) => {
        const entry = {
          id: `${pkt.timestamp}-${pkt.device_id}-${prev.length}`,
          ...pkt,
        };
        const updated = [entry, ...prev];
        return updated.slice(0, MAX_TIMELINE);
      });
    } else {
      setNormalCount((c) => c + 1);
    }

    if (pkt.quarantined) {
      setQuarantineCount((c) => c + 1);
      showToast(
        `${pkt.device_id} quarantined`,
        "linear-gradient(135deg,#f59e0b,#f97316)"
      );
    }

    // per-device info
    setDevices((prev) => {
      const copy = { ...prev };
      const id = pkt.device_id || "unknown";
      const existing = copy[id] || {
        id,
        type: pkt.device_type,
        protocol: pkt.protocol,
        totalPackets: 0,
        attackCount: 0,
        lastStatus: "Normal",
        quarantined: false,
        threat_score: 0,
        lastSeen: pkt.timestamp,
      };
      existing.totalPackets += 1;
      if (pkt.label === "Attack") existing.attackCount += 1;
      existing.lastStatus = pkt.label;
      existing.quarantined = pkt.quarantined;
      existing.threat_score = pkt.threat_score ?? 0;
      existing.protocol = pkt.protocol;
      existing.type = pkt.device_type;
      existing.lastSeen = pkt.timestamp ?? new Date().toLocaleTimeString();
      copy[id] = existing;
      return copy;
    });
  };

  // Random data generator for frontend-only mode
  const generateRandomPacket = () => {
    const devices = [
      { id: "cam_01", type: "SmartCam", protocols: ["mqtt", "udp"] },
      { id: "cam_02", type: "SmartCam", protocols: ["mqtt", "udp"] },
      { id: "thermo_01", type: "Thermostat", protocols: ["mqtt", "coap"] },
      { id: "thermo_02", type: "Thermostat", protocols: ["mqtt", "http"] },
      { id: "door_01", type: "DoorSensor", protocols: ["coap", "udp"] },
      { id: "door_02", type: "DoorSensor", protocols: ["coap", "mqtt"] },
      { id: "plug_01", type: "SmartPlug", protocols: ["mqtt", "http"] },
      { id: "plug_02", type: "SmartPlug", protocols: ["mqtt"] },
      { id: "light_01", type: "SmartLight", protocols: ["mqtt", "http"] },
      { id: "light_02", type: "SmartLight", protocols: ["mqtt"] },
      { id: "weather_01", type: "WeatherNode", protocols: ["udp", "coap"] },
      { id: "ind_01", type: "IndustrialSensor", protocols: ["mqtt", "udp"] },
      { id: "ind_02", type: "IndustrialSensor", protocols: ["mqtt"] },
      { id: "lock_01", type: "DoorLock", protocols: ["coap", "http"] },
      { id: "lock_02", type: "DoorLock", protocols: ["mqtt", "coap"] },
      { id: "meter_01", type: "EnergyMeter", protocols: ["mqtt", "http"] },
      { id: "meter_02", type: "EnergyMeter", protocols: ["coap"] },
      { id: "alarm_01", type: "FireAlarm", protocols: ["mqtt", "udp"] },
      { id: "alarm_02", type: "FireAlarm", protocols: ["coap"] },
      { id: "router_01", type: "Router", protocols: ["http", "udp"] }
    ];

    const device = devices[Math.floor(Math.random() * devices.length)];
    const protocol = device.protocols[Math.floor(Math.random() * device.protocols.length)];
    
    const highBandwidth = ["SmartCam", "IndustrialSensor", "Router"];
    const lowBandwidth = ["Thermostat", "SmartPlug", "SmartLight"];
    
    let baseRate, baseBytes;
    if (highBandwidth.includes(device.type)) {
      baseRate = Math.floor(Math.random() * 230) + 120;
      baseBytes = Math.floor(Math.random() * 7000) + 2000;
    } else if (lowBandwidth.includes(device.type)) {
      baseRate = Math.floor(Math.random() * 80) + 20;
      baseBytes = Math.floor(Math.random() * 1200) + 300;
    } else {
      baseRate = Math.floor(Math.random() * 150) + 30;
      baseBytes = Math.floor(Math.random() * 1600) + 400;
    }

    const isAttack = Math.random() < 0.12;
    let label = "Normal";
    let threatScore = Math.random() * 3;
    let quarantined = false;

    if (isAttack) {
      label = "Attack";
      threatScore = Math.random() * 4 + 6;
      baseRate *= Math.floor(Math.random() * 4) + 2;
      baseBytes *= Math.floor(Math.random() * 6) + 2;
      quarantined = Math.random() < 0.3;
    }

    return {
      timestamp: new Date().toLocaleTimeString(),
      device_id: device.id,
      device_type: device.type,
      protocol: protocol,
      packet_rate: baseRate,
      byte_rate: baseBytes,
      label: label,
      threat_score: Math.round(threatScore * 10) / 10,
      quarantined: quarantined
    };
  };

  // ===== Connection management (SSE or simulation) =====
  useEffect(() => {
    let es;
    let interval;

    const connect = () => {
      if (!isRunning) return;
      
      if (FRONTEND_ONLY) {
        // Frontend-only simulation mode
        setSrvStatus({ text: "Connected", color: "#22c55e" });
        showToast(
          "Demo mode active",
          "linear-gradient(135deg,#22c55e,#22d3ee)",
          1400
        );
        
        interval = setInterval(() => {
          const packet = generateRandomPacket();
          handlePacket(packet);
        }, Math.random() * 1500 + 800); // 0.8-2.3 second intervals
        
        setSimulationInterval(interval);
      } else {
        // Backend SSE mode
        if (es) es.close();
        es = new EventSource(`${API_BASE}/stream`);

        es.onopen = () => {
          setSrvStatus({ text: "Connected", color: "#22c55e" });
          setEsAttempts(0);
          showToast(
            "Realtime stream connected",
            "linear-gradient(135deg,#22c55e,#22d3ee)",
            1400
          );
        };

        es.onmessage = (event) => {
          if (!event.data) return;
          try {
            const pkt = JSON.parse(event.data);
            handlePacket(pkt);
          } catch (err) {
            console.error("Bad SSE data", err);
          }
        };

        es.onerror = (err) => {
          console.warn("SSE error", err);
          setSrvStatus({ text: "Reconnecting…", color: "#f97316" });
          es.close();

          setEsAttempts((prev) => {
            const attempts = prev + 1;
            const backoff = Math.min(Math.pow(1.5, attempts) * 500, MAX_BACKOFF);
            showToast(
              "Realtime stream lost — attempting recovery",
              "linear-gradient(135deg,#f97316,#fb923c)",
              1600
            );
            setTimeout(connect, backoff);
            return attempts;
          });
        };
      }
    };

    if (isRunning) {
      connect();
    } else {
      if (FRONTEND_ONLY) {
        if (simulationInterval) {
          clearInterval(simulationInterval);
          setSimulationInterval(null);
        }
        setSrvStatus({ text: "Stopped", color: "#6b7280" });
      } else {
        if (es) es.close();
        setSrvStatus({ text: "Stopped", color: "#6b7280" });
      }
    }

    return () => {
      if (es) es.close();
      if (interval) clearInterval(interval);
    };
  }, [isRunning]);

  const toggleStream = () => {
    setIsRunning(prev => {
      const newState = !prev;
      const mode = FRONTEND_ONLY ? "Simulation" : "Stream";
      showToast(
        newState ? `${mode} started` : `${mode} stopped`,
        newState 
          ? "linear-gradient(135deg,#22c55e,#22d3ee)"
          : "linear-gradient(135deg,#6b7280,#9ca3af)"
      );
      return newState;
    });
  };

  // ===== derived values =====
  const riskPercent = useMemo(() => {
    const total = normalCount + attackCount;
    if (!total) return 0;
    return Math.round((attackCount / total) * 100);
  }, [normalCount, attackCount]);

  const gaugeData = useMemo(
    () => ({
      labels: ["Threat", "Safe"],
      datasets: [
        {
          data: [riskPercent, 100 - riskPercent],
          backgroundColor: ["#f97373", "#22c55e"],
          borderWidth: 2,
        },
      ],
    }),
    [riskPercent]
  );

  const lineData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: "Packet Rate",
          data: packetRates,
          borderColor: "#22c55e",
          tension: 0.36,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          label: "Byte Rate",
          data: byteRates,
          borderColor: "#38bdf8",
          tension: 0.36,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    }),
    [labels, packetRates, byteRates]
  );

  const pieData = useMemo(() => {
    const labels = Object.keys(protocolCounts);
    return {
      labels,
      datasets: [
        {
          data: labels.map((l) => protocolCounts[l] || 0),
          backgroundColor: ["#22c55e", "#0ea5e9", "#f97373", "#facc15"],
          borderWidth: 1,
        },
      ],
    };
  }, [protocolCounts]);

  const deviceList = useMemo(() => {
    const arr = Object.values(devices);
    return arr
      .sort(
        (a, b) =>
          (b.threat_score || 0) - (a.threat_score || 0) ||
          b.attackCount - a.attackCount
      )
      .slice(0, 6);
  }, [devices]);

  const totalDevices = Object.keys(devices).length;
  const highRiskDevices = deviceList.filter(
    (d) => (d.threat_score || 0) >= 7 || d.attackCount >= 3
  ).length;

  // ===== helpers for reports/intel =====
  const exportTableCsv = () => {
    if (!packets.length) {
      showToast(
        "No data to export",
        "linear-gradient(135deg,#f59e0b,#f97316)"
      );
      return;
    }
    let csv =
      "Timestamp,Device ID,Device Type,Protocol,Packet Rate,Byte Rate,Status,Threat Score\n";
    packets.forEach((p) => {
      const row = [
        p.timestamp,
        p.device_id,
        p.device_type,
        p.protocol,
        p.packet_rate,
        p.byte_rate,
        p.label + (p.quarantined ? " (Q)" : ""),
        p.threat_score,
      ]
        .map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`)
        .join(",");
      csv += row + "\n";
    });

    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `intelliguard-live-${new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[:T]/g, "-")}.csv`;
    a.click();
    showToast(
      "Exported live traffic CSV",
      "linear-gradient(135deg,#22c55e,#22d3ee)"
    );
  };

  const downloadReport = async (period) => {
    if (FRONTEND_ONLY) {
      // Generate mock CSV report
      const csvData = packets.slice(0, 50).map(p => 
        `${p.timestamp},${p.device_id},${p.device_type},${p.protocol},${p.packet_rate},${p.byte_rate},${p.label},${p.threat_score}`
      ).join('\n');
      
      const csv = `Timestamp,Device ID,Device Type,Protocol,Packet Rate,Byte Rate,Status,Threat Score\n${csvData}`;
      const blob = new Blob([csv], { type: "text/csv" });
      const a = document.createElement("a");
      const ts = new Date().toISOString().slice(0, 10);
      a.href = URL.createObjectURL(blob);
      a.download = `intelliguard-${period}-report-${ts}.csv`;
      a.click();
      setReportDate(new Date().toLocaleDateString());
      showToast(
        `${period.charAt(0).toUpperCase() + period.slice(1)} report downloaded`,
        "linear-gradient(135deg,#22c55e,#22d3ee)"
      );
      return;
    }
    
    try {
      const res = await fetch(`${API_BASE}/api/report/${period}?format=csv`);
      if (!res.ok) {
        showToast(
          `Failed to generate ${period} report`,
          "linear-gradient(135deg,#f97316,#fb923c)"
        );
        return;
      }
      const blob = await res.blob();
      const a = document.createElement("a");
      const ts = new Date().toISOString().slice(0, 10);
      a.href = URL.createObjectURL(blob);
      a.download = `intelliguard-${period}-report-${ts}.csv`;
      a.click();
      setReportDate(new Date().toLocaleDateString());
      showToast(
        `${period.charAt(0).toUpperCase() + period.slice(1)} report downloaded`,
        "linear-gradient(135deg,#22c55e,#22d3ee)"
      );
    } catch (e) {
      console.error(e);
      showToast(
        "Error generating report",
        "linear-gradient(135deg,#f97316,#fb923c)"
      );
    }
  };

  const viewDailyJson = async () => {
    if (FRONTEND_ONLY) {
      const mockData = {
        date: new Date().toISOString().slice(0, 10),
        total_packets: normalCount + attackCount,
        normal_packets: normalCount,
        attack_packets: attackCount,
        devices_monitored: Object.keys(devices).length,
        protocols: protocolCounts,
        top_threats: Object.values(devices).filter(d => d.attackCount > 0).slice(0, 5)
      };
      console.log("Daily Report JSON:", mockData);
      showToast(
        "Daily JSON summary logged in console",
        "linear-gradient(135deg,#0ea5e9,#22d3ee)"
      );
      return;
    }
    
    try {
      const res = await fetch(`${API_BASE}/api/report/daily?format=json`);
      if (!res.ok) {
        showToast(
          "Failed to fetch JSON summary",
          "linear-gradient(135deg,#f97316,#fb923c)"
        );
        return;
      }
      const data = await res.json();
      console.log("Daily Report JSON:", data);
      showToast(
        "Daily JSON summary logged in console",
        "linear-gradient(135deg,#0ea5e9,#22d3ee)"
      );
    } catch (e) {
      console.error(e);
      showToast(
        "Error fetching JSON summary",
        "linear-gradient(135deg,#f97316,#fb923c)"
      );
    }
  };

  const runIntel = async () => {
    setIntel({ loading: true });
    
    if (FRONTEND_ONLY) {
      // Mock threat intelligence for demo
      setTimeout(() => {
        const highRiskDevs = Object.values(devices).filter(d => d.threat_score >= 7).map(d => d.id);
        const quarantinedDevs = Object.values(devices).filter(d => d.quarantined).map(d => d.id);
        
        setIntel({
          risk_score: Math.min(95, Math.max(15, attackCount * 8 + Math.random() * 20)),
          total_packets: normalCount + attackCount,
          total_attacks: attackCount,
          high_risk_devices: highRiskDevs.slice(0, 3),
          quarantined_devices: quarantinedDevs,
          attack_patterns: {
            "DoS": Math.floor(attackCount * 0.4),
            "Exfiltration": Math.floor(attackCount * 0.3),
            "Spoofing": Math.floor(attackCount * 0.2),
            "Scanning": Math.floor(attackCount * 0.1)
          }
        });
        showToast(
          "Threat intelligence updated",
          "linear-gradient(135deg,#22c55e,#22d3ee)"
        );
      }, 1500);
      return;
    }
    
    try {
      const res = await fetch(`${API_BASE}/api/intel/analyze`);
      if (!res.ok) {
        setIntel({ error: true });
        showToast(
          "Threat intel error",
          "linear-gradient(135deg,#f97316,#fb923c)"
        );
        return;
      }
      const data = await res.json();
      setIntel(data);
      showToast(
        "Threat intelligence updated",
        "linear-gradient(135deg,#22c55e,#22d3ee)"
      );
    } catch (e) {
      console.error(e);
      setIntel({ error: true });
      showToast(
        "Threat intel error",
        "linear-gradient(135deg,#f97316,#fb923c)"
      );
    }
  };

  // ===== render router layout =====
  return (
    <div className="app-shell">
      {/* background layers */}
      <div className="cyber-grid" />
      <div className="glow-orb -top-10 -left-10 absolute" />
      <div className="glow-orb bottom-0 right-0 absolute opacity-70" />

      {/* HEADER */}
      <Header srvStatus={srvStatus} isRunning={isRunning} toggleStream={toggleStream} />

      {/* LAYOUT: sidebar + routed content */}
      <div className="max-w-6xl mx-auto px-4 pb-10 relative z-10 flex flex-col lg:flex-row gap-5">
        <Sidebar
          totalDevices={totalDevices}
          highRiskDevices={highRiskDevices}
          timelineCount={timeline.length}
        />

        <main className="flex-1 space-y-4 lg:space-y-6">
          <Routes>
            <Route
              path="/"
              element={<Navigate to="/overview" replace />}
            />
            <Route
              path="/overview"
              element={
                <OverviewPage
                  normalCount={normalCount}
                  attackCount={attackCount}
                  quarantineCount={quarantineCount}
                  riskPercent={riskPercent}
                  gaugeData={gaugeData}
                  lineData={lineData}
                />
              }
            />
            <Route
              path="/traffic"
              element={
                <TrafficPage
                  pieData={pieData}
                  packets={packets}
                  exportTableCsv={exportTableCsv}
                  setPackets={setPackets}
                />
              }
            />
            <Route
              path="/devices"
              element={
                <DevicesPage
                  deviceList={deviceList}
                  timeline={timeline}
                />
              }
            />
            <Route
              path="/reports"
              element={
                <ReportsPage
                  downloadReport={downloadReport}
                  viewDailyJson={viewDailyJson}
                  reportDate={reportDate}
                  intel={intel}
                  runIntel={runIntel}
                />
              }
            />
            {/* fallback */}
            <Route
              path="*"
              element={<Navigate to="/overview" replace />}
            />
          </Routes>
        </main>
      </div>

      {toast && (
        <div className="toast" style={{ background: toast.bg }}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}

/* ================== LAYOUT COMPONENTS ================== */

function Header({ srvStatus, isRunning, toggleStream }) {
  return (
    <header className="max-w-6xl mx-auto py-4 lg:py-6 px-4 relative z-10">
      <div className="glass-panel-strong px-3 lg:px-5 py-3 lg:py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 lg:gap-4">
        <div className="flex items-center gap-3 lg:gap-4">
          <div className="w-10 h-10 lg:w-12 lg:h-12 rounded-xl bg-gradient-to-br from-cyan-400 via-sky-500 to-blue-700 flex items-center justify-center shadow-[0_0_35px_rgba(34,211,238,0.75)] ring-2 ring-cyan-300/50">
            <Shield className="w-5 h-5 lg:w-6 lg:h-6 text-slate-950" strokeWidth={1.8} />
          </div>
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
              <h1 className="text-xl lg:text-2xl font-extrabold text-cyan-200 leading-tight tracking-tight">
                IntelliGuard SOC
              </h1>
              <span className="px-2 py-0.5 rounded-full text-[0.6rem] lg:text-[0.65rem] bg-emerald-500/10 text-emerald-300 border border-emerald-500/40 uppercase tracking-wide w-fit">
                {FRONTEND_ONLY ? "Demo" : "Live"}
              </span>
            </div>
            <p className="text-[0.7rem] lg:text-xs text-slate-400 mt-1 flex items-center gap-2">
              <Wifi className="w-3 h-3 text-sky-400" />
              <span className="hidden sm:inline">{FRONTEND_ONLY ? "Simulated IoT Threat & Anomaly Monitoring" : "Real-time IoT Threat & Anomaly Monitoring"}</span>
              <span className="sm:hidden">IoT Security Monitor</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 lg:gap-3 w-full sm:w-auto justify-between sm:justify-end">
          <div
            className="px-2 lg:px-3 py-1.5 rounded-full text-[0.7rem] lg:text-xs bg-slate-900/80 border border-slate-600/70 flex items-center gap-2"
            style={{ color: srvStatus.color }}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="hidden sm:inline">{srvStatus.text}</span>
          </div>
          <button
            onClick={toggleStream}
            className={`px-2 lg:px-3 py-1.5 rounded-full text-[0.7rem] lg:text-xs flex items-center gap-1 ${
              isRunning
                ? "bg-red-600/90 border border-red-500/70 text-red-100 hover:bg-red-500/10"
                : "bg-green-600/90 border border-green-500/70 text-green-100 hover:bg-green-500/10"
            }`}
          >
            {isRunning ? (
              <><Pause className="w-3 h-3 lg:w-3.5 lg:h-3.5" /><span className="hidden sm:inline">Stop</span></>
            ) : (
              <><Play className="w-3 h-3 lg:w-3.5 lg:h-3.5" /><span className="hidden sm:inline">Start</span></>
            )}
          </button>
          <button
            onClick={() => {
              // Reset all state instead of page reload
              setPackets([]);
              setLabels([]);
              setPacketRates([]);
              setByteRates([]);
              setProtocolCounts({ mqtt: 0, coap: 0, http: 0, udp: 0 });
              setDevices({});
              setTimeline([]);
              setNormalCount(0);
              setAttackCount(0);
              setQuarantineCount(0);
              setIntel(null);
              showToast("Dashboard refreshed", "linear-gradient(135deg,#22c55e,#22d3ee)");
            }}
            className="px-2 lg:px-3 py-1.5 rounded-full bg-slate-900/90 border border-sky-500/70 text-[0.7rem] lg:text-xs text-sky-200 hover:bg-sky-500/10 flex items-center gap-1"
          >
            <RefreshCcw className="w-3 h-3 lg:w-3.5 lg:h-3.5" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>
    </header>
  );
}

function Sidebar({ totalDevices, highRiskDevices, timelineCount }) {

  return (
    <aside className="flex flex-col w-full lg:w-52 lg:mr-1 lg:sticky lg:top-20 lg:h-[520px] glass-panel px-3 py-4 text-xs text-slate-300 mb-4 lg:mb-0">
      <div className="flex items-center gap-2 mb-3 font-semibold text-slate-200">
        <Cpu className="w-4 h-4 text-sky-400" />
        Console
      </div>

      <SidebarLink to="/overview" label="Overview" />
      <SidebarLink to="/traffic" label="Traffic Stream" />
      <SidebarLink to="/devices" label="Devices" />
      <SidebarLink to="/reports" label="Reports & Intel" />

      <div className="mt-4 pt-3 border-t border-slate-700/80 text-[0.7rem] space-y-1">
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Devices</span>
          <span className="text-sky-300 font-semibold">{totalDevices}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">High-Risk</span>
          <span className="text-red-400 font-semibold">{highRiskDevices}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Timeline</span>
          <span className="text-emerald-300 font-semibold">
            {timelineCount} events
          </span>
        </div>
      </div>
    </aside>
  );
}

function SidebarLink({ to, label }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `text-left px-3 py-1.5 rounded-md text-[0.75rem] mb-1 transition ${
          isActive
            ? "bg-slate-800/90 text-sky-200"
            : "text-slate-300 hover:bg-slate-800/80 hover:text-sky-200"
        }`
      }
    >
      {label}
    </NavLink>
  );
}

/* ================== PAGES ================== */

function OverviewPage({
  normalCount,
  attackCount,
  quarantineCount,
  riskPercent,
  gaugeData,
  lineData,
}) {
  return (
    <>
      {/* Stats */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 lg:gap-4">
        <StatsCard
          title="Normal Traffic"
          badge="HEALTHY"
          value={normalCount}
          valueClass="text-emerald-400"
          subtitle="Packets classified as benign"
          dotClass="bg-emerald-400"
        />
        <StatsCard
          title="Detected Attacks"
          badge="THREATS"
          value={attackCount}
          valueClass="text-red-400"
          subtitle="ML engine flagged malicious events"
          dotClass="bg-red-400"
        />
        <StatsCard
          title="Quarantined Devices"
          badge="ISOLATED"
          value={quarantineCount}
          valueClass="text-amber-300"
          subtitle="Devices temporarily blocked from network"
          dotClass="bg-amber-400"
        />
      </section>

      {/* Gauge + Line */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
        <div className="glass-panel px-6 py-5 flex flex-col items-center justify-center">
          <h3 className="section-heading">
            <span className="text-pink-300">🧠 Network Threat Level</span>
          </h3>
          <p className="subtext mt-1">
            Aggregate ML &amp; anomaly scores vs safe baseline
          </p>
          <div className="gauge-wrapper mt-3">
            <Doughnut
              data={gaugeData}
              options={{
                cutout: "82%",
                plugins: { legend: { display: false } },
                maintainAspectRatio: false,
              }}
            />
          </div>
          <div className="gauge-label text-sm mt-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <span>
              Current risk:&nbsp;
              <span
                className={
                  riskPercent < 25
                    ? "text-emerald-400"
                    : riskPercent < 60
                    ? "text-amber-300"
                    : "text-red-400"
                }
              >
                {riskPercent}%
              </span>
            </span>
          </div>
        </div>

        <div className="lg:col-span-2 glass-panel px-5 py-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="section-heading">📈 Live Network Metrics</h3>
            <span className="subtext">
              Last {HISTORY} samples • packet &amp; byte rate
            </span>
          </div>
          <div className="h-52">
            <Line
              data={lineData}
              options={{
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    labels: { color: "#cfe9f5", font: { size: 10 } },
                  },
                },
                scales: {
                  x: {
                    ticks: {
                      color: "#64748b",
                      maxRotation: 45,
                      minRotation: 45,
                    },
                  },
                  y: { ticks: { color: "#64748b" } },
                },
              }}
            />
          </div>
        </div>
      </section>
    </>
  );
}

function TrafficPage({ pieData, packets, exportTableCsv, setPackets }) {
  return (
    <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
      <div className="glass-panel px-5 py-4 flex flex-col items-center">
        <h3 className="section-heading mb-1">📊 Protocol Distribution</h3>
        <p className="subtext mb-3">
          Relative share of MQTT, CoAP, HTTP &amp; UDP traffic
        </p>
        <div className="protocol-wrapper w-full flex items-center justify-center">
          <Pie
            data={pieData}
            options={{
              plugins: {
                legend: {
                  labels: { color: "#cfe9f5", font: { size: 10 } },
                  position: "bottom",
                },
              },
            }}
          />
        </div>
      </div>

      <div className="lg:col-span-2 glass-panel px-4 lg:px-5 py-4">
        <h3 className="section-heading mb-1">📡 Live IoT Traffic Stream</h3>
        <p className="subtext mb-3">
          Most recent packets from simulated devices — ideal for demoing IoT
          threat monitoring.
        </p>

        <div className="flex items-center gap-2 mb-3">
          <button
            onClick={exportTableCsv}
            className="px-3 py-1.5 rounded-md bg-sky-600 hover:bg-sky-500 text-xs font-medium"
          >
            📥 Export Live CSV
          </button>
          <button
            onClick={() => setPackets([])}
            className="px-3 py-1.5 rounded-md bg-slate-900 border border-slate-600 text-xs hover:bg-slate-800"
          >
            Clear Table
          </button>
        </div>

        <div className="overflow-x-auto overflow-y-auto max-h-[340px] custom-scroll table-wrapper rounded-xl border border-slate-800/90">
          <table className="w-full text-xs lg:text-sm min-w-[600px]">
            <thead className="sticky top-0">
              <tr>
                <th className="p-2 text-left">Time</th>
                <th className="p-2 text-left">Device</th>
                <th className="p-2 text-left">Type</th>
                <th className="p-2 text-left">Proto</th>
                <th className="p-2 text-right">Pkt/s</th>
                <th className="p-2 text-right">Bytes/s</th>
                <th className="p-2 text-center">Status</th>
                <th className="p-2 text-right">Score</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt, idx) => {
                const isAttack = pkt.label === "Attack";
                const color = pkt.quarantined
                  ? "text-amber-300"
                  : isAttack
                  ? "text-red-400 font-semibold"
                  : "text-emerald-400";

                return (
                  <tr key={idx}>
                    <td>{pkt.timestamp}</td>
                    <td>{pkt.device_id}</td>
                    <td>{pkt.device_type}</td>
                    <td>{pkt.protocol}</td>
                    <td className="text-right">{pkt.packet_rate ?? 0}</td>
                    <td className="text-right">{pkt.byte_rate ?? 0}</td>
                    <td className={`text-center ${color}`}>
                      {pkt.label}
                      {pkt.quarantined ? " (Q)" : ""}
                    </td>
                    <td className="text-right">{pkt.threat_score ?? 0}</td>
                  </tr>
                );
              })}
              {!packets.length && (
                <tr>
                  <td
                    colSpan={8}
                    className="text-center text-xs text-slate-500 py-4"
                  >
                    Waiting for live IoT traffic…
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function DevicesPage({ deviceList, timeline }) {
  return (
    <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
      <div className="glass-panel px-5 py-4 lg:col-span-2">
        <h3 className="section-heading mb-1">🧩 Device Overview</h3>
        <p className="subtext mb-3">
          Top IoT devices ranked by threat score &amp; attack frequency.
        </p>
        {deviceList.length === 0 ? (
          <p className="text-xs text-slate-500">
            No devices observed yet. Traffic will populate this section.
          </p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-3">
            {deviceList.map((d) => (
              <DeviceCard key={d.id} device={d} />
            ))}
          </div>
        )}
      </div>

      <div className="glass-panel px-5 py-4">
        <h3 className="section-heading mb-1 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400" />
          <span>Live Threat Timeline</span>
        </h3>
        <p className="subtext mb-3">
          Most recent attack events with device, protocol &amp; threat score.
        </p>
        <div className="space-y-2 max-h-72 overflow-y-auto custom-scroll pr-1">
          {timeline.length === 0 && (
            <p className="text-xs text-slate-500">
              No attacks observed yet. When an attack is detected, it will
              appear here.
            </p>
          )}
          {timeline.map((evt) => (
            <TimelineItem key={evt.id} evt={evt} />
          ))}
        </div>
      </div>
    </section>
  );
}

function ReportsPage({
  downloadReport,
  viewDailyJson,
  reportDate,
  intel,
  runIntel,
}) {
  return (
    <section className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6 mt-4">
      <div className="glass-panel px-5 py-5">
        <h3 className="section-heading mb-1">📄 Security Reports</h3>
        <p className="text-sm text-slate-300 mb-3">
          Generate analyst-ready CSV summaries of patterns, anomalies and
          overall network posture.
        </p>

        <div className="flex flex-wrap gap-3 mb-4">
          <button
            onClick={() => downloadReport("daily")}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 rounded-md text-xs font-medium"
          >
            ⬇️ Daily Report (CSV)
          </button>
          <button
            onClick={() => downloadReport("weekly")}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 rounded-md text-xs font-medium"
          >
            ⬇️ Weekly Report (CSV)
          </button>
          <button
            onClick={() => downloadReport("monthly")}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 rounded-md text-xs font-medium"
          >
            ⬇️ Monthly Report (CSV)
          </button>
        </div>

        <button
          onClick={viewDailyJson}
          className="px-3 py-1.5 rounded-md bg-slate-900 border border-slate-600 text-[0.7rem] hover:bg-slate-800"
        >
          🔍 Log Daily JSON Summary (console)
        </button>

        <p className="text-xs text-slate-500 mt-3">
          📅 Last generated: <span>{reportDate}</span>
        </p>
      </div>

      <div className="glass-panel px-5 py-5">
        <div className="flex items-center justify-between mb-2">
          <h3 className="section-heading">🌐 Threat Intelligence</h3>
          <button
            onClick={runIntel}
            className="px-3 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 text-xs font-medium text-emerald-950"
          >
            Analyze
          </button>
        </div>
        <p className="text-sm text-slate-300 mb-3">
          Derive high-level insights from recent traffic — risk score, dominant
          attack patterns and high-risk IoT devices.
        </p>
        <div className="text-xs text-slate-200 space-y-1">
          {!intel && <div>No analysis yet. Click Analyze.</div>}
          {intel?.loading && <div>Analyzing recent traffic…</div>}
          {intel?.error && (
            <div className="text-red-400">
              Failed to generate threat intelligence.
            </div>
          )}
          {intel &&
            !intel.loading &&
            !intel.error &&
            intel.risk_score !== undefined && (
              <>
                <div>
                  Risk Score:&nbsp;
                  <span className="font-semibold text-emerald-300">
                    {intel.risk_score}/100
                  </span>
                </div>
                <div>Total Packets (window): {intel.total_packets}</div>
                <div>
                  Total Attacks:&nbsp;
                  <span className="text-red-400">
                    {intel.total_attacks}
                  </span>
                </div>
                <div>
                  High-risk Devices:&nbsp;
                  {intel.high_risk_devices?.length
                    ? intel.high_risk_devices.join(", ")
                    : "None"}
                </div>
                <div>
                  Quarantined Devices:&nbsp;
                  {intel.quarantined_devices?.length
                    ? intel.quarantined_devices.join(", ")
                    : "None"}
                </div>
                <div className="mt-2">
                  Attack Patterns:
                  <pre className="whitespace-pre-wrap mt-1 bg-slate-900/70 rounded-md p-2 border border-slate-700/80 text-[0.7rem]">
                    {JSON.stringify(intel.attack_patterns || {}, null, 2)}
                  </pre>
                </div>
              </>
            )}
        </div>
      </div>
    </section>
  );
}

/* ================== REUSABLE CARDS ================== */

function StatsCard({
  title,
  badge,
  value,
  subtitle,
  valueClass = "text-cyan-300",
  dotClass = "bg-cyan-300",
}) {
  return (
    <div className="stat-card">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${dotClass}`} />
          <div className="text-sm text-slate-200 font-semibold">
            {title}
          </div>
        </div>
        <span className="px-2 py-0.5 rounded-full bg-slate-900/80 text-[0.65rem] text-slate-300 border border-slate-600/80 uppercase tracking-wide">
          {badge}
        </span>
      </div>
      <div className={`text-3xl font-extrabold ${valueClass}`}>{value}</div>
      <p className="mt-3 text-xs text-slate-400">{subtitle}</p>
    </div>
  );
}

function DeviceCard({ device }) {
  const risk =
    device.threat_score >= 9
      ? "Critical"
      : device.threat_score >= 7
      ? "High"
      : device.threat_score >= 4
      ? "Elevated"
      : "Low";

  const riskColor =
    risk === "Critical"
      ? "text-red-400"
      : risk === "High"
      ? "text-amber-300"
      : risk === "Elevated"
      ? "text-sky-300"
      : "text-emerald-300";

  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900/70 px-3.5 py-3 text-[0.78rem] space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="font-semibold text-slate-100">{device.id}</div>
        <span
          className={`px-2 py-0.5 rounded-full border text-[0.65rem] ${riskColor} border-current`}
        >
          {risk}
        </span>
      </div>
      <div className="flex items-center justify-between text-slate-400">
        <span>{device.type}</span>
        <span className="uppercase text-sky-300">{device.protocol}</span>
      </div>
      <div className="flex items-center justify-between text-slate-400">
        <span>Threat score</span>
        <span className="text-slate-100 font-semibold">
          {device.threat_score?.toFixed?.(1) ?? device.threat_score}
        </span>
      </div>
      <div className="flex items-center justify-between text-slate-400">
        <span>Attacks</span>
        <span className="text-red-300 font-semibold">
          {device.attackCount}
        </span>
      </div>
      <div className="flex items-center justify-between text-slate-400">
        <span>Packets</span>
        <span className="text-slate-200">{device.totalPackets}</span>
      </div>
      <div className="flex items-center justify-between text-slate-500 text-[0.7rem] pt-1">
        <span>Last seen</span>
        <span>{device.lastSeen}</span>
      </div>
      {device.quarantined && (
        <div className="mt-1 text-[0.7rem] text-amber-300 flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-300" />
          Quarantined
        </div>
      )}
    </div>
  );
}

function TimelineItem({ evt }) {
  return (
    <div className="flex gap-2 text-[0.8rem]">
      <div className="flex flex-col items-center pt-1">
        <span className="w-2 h-2 rounded-full bg-red-400" />
        <span className="flex-1 w-px bg-slate-700/80" />
      </div>
      <div className="flex-1 pb-2 border-b border-slate-800/80">
        <div className="flex justify-between items-center">
          <span className="text-slate-300 font-semibold">
            {evt.device_id}
          </span>
          <span className="text-slate-500 text-[0.7rem]">
            {evt.timestamp}
          </span>
        </div>
        <div className="flex justify-between items-center text-[0.75rem] mt-0.5">
          <span className="text-slate-400">
            Label:{" "}
            <span className="text-red-300 font-semibold">
              {evt.label}
            </span>
          </span>
          <span className="text-slate-400">
            Proto:&nbsp;
            <span className="uppercase text-sky-300">
              {evt.protocol}
            </span>
          </span>
        </div>
        <div className="flex justify-between items-center text-[0.75rem] mt-0.5">
          <span className="text-slate-400">
            Threat score:&nbsp;
            <span className="text-amber-300 font-semibold">
              {evt.threat_score}
            </span>
          </span>
          {evt.quarantined && (
            <span className="text-amber-300 text-[0.7rem]">
              Device quarantined
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
