from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import pandas as pd
import pickle
import json
import os
import time
import traceback
import io
import csv
from queue import Queue
from collections import defaultdict, Counter
from datetime import datetime

# === Flask App ===
app = Flask(__name__)
CORS(app)

BASE_PATH = os.path.dirname(__file__)

# ---------- Safe Loader ----------
def safe_load(name: str):
    """
    Try to load a pickle file from:
      back_end/model/
      or ../model/
    """
    paths = [
        os.path.join(BASE_PATH, "model", name),
        os.path.join(BASE_PATH, "..", "model", name),
    ]
    for p in paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                print(f"✔ Loaded: {name} from {p}")
                return pickle.load(f)
    print(f"⚠️ Missing model asset: {name}")
    return None


# ---------- Load ML Assets ----------
model = safe_load("iot_model.pkl")
scaler = safe_load("scaler.pkl")
encoder_protocol = safe_load("encoder_protocol.pkl")
encoder_device = safe_load("encoder_device.pkl")
iso_forest = safe_load("isoforest.pkl")
meta = safe_load("meta.pkl")

# ---------- Globals ----------
packet_queue = Queue()

# in-memory history for reports + intel (each entry is a pkt dict)
packet_history = []

device_state = defaultdict(
    lambda: {
        "threat_score": 0.0,
        "quarantined": False,
        "last_seen": 0.0,
        "last_alert": 0.0,
    }
)

THREAT_THRESHOLD = 7.0
RECOVERY_TIME = 60  # auto unquarantine after 60s


# ---------- SSE STREAM ----------
@app.route("/stream")
def stream():
    def event_stream():
        while True:
            pkt = packet_queue.get()
            yield f"data: {json.dumps(pkt)}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")


# ---------- Encoding Helpers ----------
def encode_protocol(proto) -> float:
    try:
        if encoder_protocol is None:
            return 0.0
        proto = str(proto).lower()
        classes = [x.lower() for x in encoder_protocol.classes_]
        if proto in classes:
            idx = classes.index(proto)
            return encoder_protocol.transform(
                [encoder_protocol.classes_[idx]]
            )[0]
        return encoder_protocol.transform(
            [encoder_protocol.classes_[0]]
        )[0]
    except Exception:
        return 0.0


def encode_device(dtype) -> float:
    try:
        if encoder_device is None:
            return 0.0
        dtype = str(dtype)
        classes = [str(x) for x in encoder_device.classes_]
        if dtype in classes:
            idx = classes.index(dtype)
            return encoder_device.transform(
                [encoder_device.classes_[idx]]
            )[0]
        return encoder_device.transform(
            [encoder_device.classes_[0]]
        )[0]
    except Exception:
        return 0.0


# ---------- Main Packet API ----------
@app.route("/api/packet", methods=["POST"])
def receive_packet():
    try:
        data = request.get_json(force=True)
        device_id = data.get("device_id", "unknown")
        proto = data.get("protocol", "mqtt")
        dtype = data.get("device_type", "UnknownDevice")
        sim_attack_type = data.get("attack_type", "Normal")  # from simulator

        # State entry
        st = device_state[device_id]
        now = time.time()
        st["last_seen"] = now

        # Check quarantine status
        if st["quarantined"]:
            if (now - st["last_alert"]) > RECOVERY_TIME:
                # auto recover
                st["quarantined"] = False
                st["threat_score"] = 0.0
                print(f"✅ Auto-recovered {device_id}")
            else:
                # still quarantined → block packet
                print(f"🚫 {device_id} blocked (quarantined)")
                return jsonify({"status": "blocked", "device": device_id})

        # Build feature vector
        features = {
            "packet_rate": float(data.get("packet_rate", 0)),
            "byte_rate": float(data.get("byte_rate", 0)),
            "packet_size": float(data.get("packet_size", 0)),
            "connection_duration": float(data.get("connection_duration", 0)),
            "protocol_enc": encode_protocol(proto),
            "device_type_enc": encode_device(dtype),
            "source_port": float(data.get("source_port", 0)),
            "destination_port": float(data.get("destination_port", 0)),
        }

        df = pd.DataFrame([features])

        # ML prediction with fallback
        scaled = df
        if scaler is not None:
            scaled = scaler.transform(df)

        if scaler is not None and model is not None:
            pred = model.predict(scaled)[0]
            pred_label = "Attack" if pred == 1 else "Normal"
        else:
            # fallback: basic rule-based
            pred_label = "Attack" if (
                features["packet_rate"] > 800
                or features["byte_rate"] > 10000
            ) else "Normal"

        # anomaly detection
        anomaly_flag = False
        if iso_forest is not None:
            try:
                if iso_forest.predict(scaled)[0] == -1:
                    anomaly_flag = True
            except Exception:
                pass

        # threat scoring
        threat_inc = 0.0
        if pred_label == "Attack":
            threat_inc += 3.0
        if anomaly_flag:
            threat_inc += 2.0
        if (
            features["packet_rate"] > 900
            or features["byte_rate"] > 12000
        ):
            threat_inc += 1.0

        st["threat_score"] = st["threat_score"] * 0.90 + threat_inc

        # quarantine check
        if st["threat_score"] >= THREAT_THRESHOLD:
            st["quarantined"] = True
            st["last_alert"] = now
            print(
                f"⚠️ QUARANTINED: {device_id} "
                f"(score {st['threat_score']:.2f})"
            )

        # final packet data (this is what frontend + reports see)
        pkt = {
            # precise timestamp with milliseconds → avoids duplicate x-axis labels
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "epoch": now,  # for time-window filtering
            "device_id": device_id,
            "device_type": dtype,
            "protocol": proto,
            "packet_rate": features["packet_rate"],
            "byte_rate": features["byte_rate"],
            "label": pred_label,
            "anomaly": anomaly_flag,
            "threat_score": round(st["threat_score"], 2),
            "quarantined": st["quarantined"],
            "sim_attack_type": sim_attack_type,
        }

        # store in history (for reports & intel)
        packet_history.append(pkt)

        # push packet to SSE stream
        packet_queue.put(pkt)

        # console output
        print(
            f"[{device_id}] {proto} => {pred_label} "
            f"(Score={pkt['threat_score']})"
        )

        return jsonify(pkt)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ---------- Unquarantine Endpoint ----------
@app.route("/api/unquarantine", methods=["POST"])
def unquarantine_device():
    try:
        data = request.get_json(force=True)
        device_id = data.get("device_id")

        if device_id not in device_state:
            return jsonify({"message": "Device not found"}), 404

        device_state[device_id]["quarantined"] = False
        device_state[device_id]["threat_score"] = 0.0
        device_state[device_id]["last_alert"] = 0.0

        print(f"✅ Manually unquarantined: {device_id}")

        return jsonify({"message": f"{device_id} unquarantined"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------- Helpers for reports / intel ----------
def _filter_by_window(seconds):
    """Return packets from the last `seconds` seconds."""
    cutoff = time.time() - seconds
    return [p for p in packet_history if p.get("epoch", 0) >= cutoff]


def _build_report(seconds):
    packets = _filter_by_window(seconds)
    total = len(packets)
    attacks = sum(1 for p in packets if p.get("label") == "Attack")
    normal = sum(1 for p in packets if p.get("label") == "Normal")
    quarantined_devices = sorted(
        {p["device_id"] for p in packets if p.get("quarantined")}
    )
    proto_counts = Counter(p.get("protocol", "unknown") for p in packets)
    device_attack_counts = Counter(
        p["device_id"] for p in packets if p.get("label") == "Attack"
    )

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "window_seconds": seconds,
        "total_packets": total,
        "normal": normal,
        "attacks": attacks,
        "attack_ratio": round((attacks / total) * 100, 2) if total else 0.0,
        "quarantined_devices": list(quarantined_devices),
        "protocol_distribution": dict(proto_counts),
        "top_attack_devices": [
            {"device_id": did, "attacks": cnt}
            for did, cnt in device_attack_counts.most_common(5)
        ],
    }
    return report


def _report_to_csv(report_dict):
    """Convert summary report to a simple metrics CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["metric", "value"])

    writer.writerow(["generated_at", report_dict["generated_at"]])
    writer.writerow(["window_seconds", report_dict["window_seconds"]])
    writer.writerow(["total_packets", report_dict["total_packets"]])
    writer.writerow(["normal", report_dict["normal"]])
    writer.writerow(["attacks", report_dict["attacks"]])
    writer.writerow(["attack_ratio_percent", report_dict["attack_ratio"]])
    writer.writerow(
        ["quarantined_devices", ";".join(report_dict["quarantined_devices"])]
    )

    # protocol distribution
    for proto, count in report_dict["protocol_distribution"].items():
        writer.writerow([f"protocol_{proto}", count])

    # top attack devices
    for idx, dev in enumerate(report_dict["top_attack_devices"], start=1):
        writer.writerow(
            [f"top_attack_device_{idx}", f"{dev['device_id']} ({dev['attacks']})"]
        )

    return output.getvalue()


def _build_intel(seconds=3600):
    """Generate threat intelligence summary from recent packets."""
    packets = _filter_by_window(seconds)
    total = len(packets)
    attacks = [p for p in packets if p.get("label") == "Attack"]

    # overall risk score (0–100)
    if total:
        base = (len(attacks) / total) * 80
    else:
        base = 0.0
    quarantined = {p["device_id"] for p in packets if p.get("quarantined")}
    risk_score = min(100, round(base + len(quarantined) * 5))

    # attack pattern types (from simulator)
    pattern_counts = Counter(
        p.get("sim_attack_type", "Normal")
        for p in attacks
        if p.get("sim_attack_type")
    )

    # protocol anomalies: high packet rate
    high_rate = [p for p in packets if p.get("packet_rate", 0) > 1000]
    proto_anom = Counter(p.get("protocol", "unknown") for p in high_rate)

    device_attack_counts = Counter(p["device_id"] for p in attacks)
    high_risk_devices = [d for d, _ in device_attack_counts.most_common(5)]

    intel = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "window_seconds": seconds,
        "risk_score": risk_score,
        "total_packets": total,
        "total_attacks": len(attacks),
        "high_risk_devices": high_risk_devices,
        "quarantined_devices": list(quarantined),
        "attack_patterns": dict(pattern_counts),
        "high_rate_protocol_anomalies": dict(proto_anom),
    }
    return intel


# ---------- Report Endpoints ----------
@app.route("/api/report/<period>")
def generate_report(period):
    """
    /api/report/daily?format=json|csv
    /api/report/weekly?format=json|csv
    /api/report/monthly?format=json|csv
    """
    period = period.lower()
    fmt = request.args.get("format", "json").lower()

    if period == "daily":
        seconds = 24 * 3600
    elif period == "weekly":
        seconds = 7 * 24 * 3600
    elif period == "monthly":
        seconds = 30 * 24 * 3600
    else:
        return jsonify({"error": "Invalid period"}), 400

    report = _build_report(seconds)

    if fmt == "csv":
        csv_text = _report_to_csv(report)
        resp = Response(csv_text, mimetype="text/csv")
        filename = f"intelliguard_{period}_report.csv"
        resp.headers["Content-Disposition"] = (
            f"attachment; filename={filename}"
        )
        return resp

    # default JSON
    return jsonify(report)


# ---------- Threat Intelligence Endpoint ----------
@app.route("/api/intel/analyze")
def analyze_intelligence():
    """
    Analyze recent (last 60 mins by default) packets and return threat intelligence.
    """
    seconds = int(request.args.get("window", 3600))
    intel = _build_intel(seconds)
    return jsonify(intel)


# ---------- Dashboard ----------
@app.route("/")
def dashboard():
    return jsonify({"message": "IoT Security Backend API"})


# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
