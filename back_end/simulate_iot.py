import requests
import random
import time
import threading

# Backend endpoint
SERVER_URL = "http://localhost:5000/api/packet"



# Each device sends a packet every 6–12 seconds (slow + realistic)
INTERVAL_RANGE = (6.0, 12.0)

# 20 IoT Devices (Realistic)
DEVICES = [
    ("cam_01", "SmartCam", ["mqtt", "udp"]),
    ("cam_02", "SmartCam", ["mqtt", "udp"]),
    ("thermo_01", "Thermostat", ["mqtt", "coap"]),
    ("thermo_02", "Thermostat", ["mqtt", "http"]),
    ("door_01", "DoorSensor", ["coap", "udp"]),
    ("door_02", "DoorSensor", ["coap", "mqtt"]),
    ("plug_01", "SmartPlug", ["mqtt", "http"]),
    ("plug_02", "SmartPlug", ["mqtt"]),
    ("light_01", "SmartLight", ["mqtt", "http"]),
    ("light_02", "SmartLight", ["mqtt"]),
    ("weather_01", "WeatherNode", ["udp", "coap"]),
    ("ind_01", "IndustrialSensor", ["mqtt", "udp"]),
    ("ind_02", "IndustrialSensor", ["mqtt"]),
    ("lock_01", "DoorLock", ["coap", "http"]),
    ("lock_02", "DoorLock", ["mqtt", "coap"]),
    ("meter_01", "EnergyMeter", ["mqtt", "http"]),
    ("meter_02", "EnergyMeter", ["coap"]),
    ("alarm_01", "FireAlarm", ["mqtt", "udp"]),
    ("alarm_02", "FireAlarm", ["coap"]),
    ("router_01", "Router", ["http", "udp"]),
]

# ~10% chance of an attack packet (calmer)
ATTACK_PROB = 0.10


def generate_packet(device_id: str, device_type: str, protocol: str) -> dict:
    """
    Generate one synthetic IoT traffic packet with optional attack behaviour.
    """

    # Base behaviour depending on device type
    high_bandwidth = ["SmartCam", "IndustrialSensor", "Router"]
    low_bandwidth = ["Thermostat", "SmartPlug", "SmartLight"]

    if device_type in high_bandwidth:
        base_rate = random.randint(120, 350)
        base_bytes = random.randint(2000, 9000)
    elif device_type in low_bandwidth:
        base_rate = random.randint(20, 100)
        base_bytes = random.randint(300, 1500)
    else:
        base_rate = random.randint(30, 180)
        base_bytes = random.randint(400, 2000)

    duration = round(random.uniform(0.2, 5.5), 2)
    attack_type = "Normal"

    # Attack simulation
    if random.random() < ATTACK_PROB:
        attack_type = random.choice(["DoS", "Exfiltration", "Spoofing", "Scanning"])

        if attack_type == "DoS":
            base_rate *= random.randint(3, 6)
            base_bytes *= random.randint(3, 6)

        elif attack_type == "Exfiltration":
            base_rate *= random.randint(2, 4)
            base_bytes *= random.randint(4, 10)
            duration = round(random.uniform(10, 40), 2)

        elif attack_type == "Spoofing":
            protocol = random.choice(["mqtt", "udp", "http"])
            base_rate *= 2
            base_bytes *= 2

        elif attack_type == "Scanning":
            base_rate = random.randint(60, 200)
            base_bytes = random.randint(300, 1200)
            duration = round(random.uniform(0.05, 1.5), 2)

    packet_size = round(base_bytes / max(1, base_rate), 2)

    return {
        "device_id": device_id,
        "device_type": device_type,
        "protocol": protocol,
        "packet_rate": base_rate,
        "byte_rate": base_bytes,
        "packet_size": packet_size,
        "connection_duration": duration,
        "source_port": random.randint(1000, 65535),
        "destination_port": random.choice([80, 443, 1883, 5683, 502]),
        "attack_type": attack_type,  # used by threat intel backend
    }


def simulate_device(device_id: str, device_type: str, protocols: list[str], start_delay: float):
    """
    Simulate one device:
      - waits a small start_delay (to avoid all devices starting together)
      - then sends packets forever with random interval within INTERVAL_RANGE
    """
    time.sleep(start_delay)
    print(f"🚀 Starting {device_id} ({device_type}) after {start_delay:.1f}s delay")

    while True:
        proto = random.choice(protocols)
        packet = generate_packet(device_id, device_type, proto)

        try:
            res = requests.post(SERVER_URL, json=packet, timeout=5)
            if res.status_code == 200:
                out = res.json()
                label = out.get("label", "Unknown")
                score = out.get("threat_score", 0)

                if label == "Attack":
                    print(f"❗[{device_id}] Attack | Score={score}")
                else:
                    print(f"✔ [{device_id}] Normal | Score={score}")

            else:
                print(f"⚠️ [{device_id}] Server returned {res.status_code}")

        except Exception as e:
            print(f"❌ [{device_id}] Error: {e}")

        # Slow, realistic interval per device
        sleep_for = random.uniform(*INTERVAL_RANGE)
        time.sleep(sleep_for)


if __name__ == "__main__":
    print("🌐 Simulating IoT devices (slow, realistic mode)...")

    # Stagger device start so they don't all flood at the same time
    for idx, (dev_id, dtype, protos) in enumerate(DEVICES):
        # 0.3–1.0s extra delay per index → nicely spread starts
        delay = random.uniform(0.3, 1.0) * idx
        t = threading.Thread(
            target=simulate_device,
            args=(dev_id, dtype, protos, delay),
            daemon=True,
        )
        t.start()

    # Keep main thread alive
    while True:
        time.sleep(1)
