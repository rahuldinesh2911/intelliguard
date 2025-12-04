# generate_dataset_realistic.py
import os
import random
import ipaddress
import time
import pandas as pd
from datetime import datetime, timedelta

os.makedirs("dataset", exist_ok=True)

# Configuration
NUM_DEVICES = 20                  # total simulated devices
RECORDS_PER_DEVICE = 300          # how many records (rows) per device
START_TIME = datetime.now() - timedelta(hours=1)
TIME_STEP_SECONDS = 2             # average time between records for a device

device_types = [
    "SmartCam", "Thermostat", "DoorSensor",
    "WeatherNode", "SmartPlug", "SmartLight",
    "IndustrialSensor", "DoorLock"
]

protocols_by_device = {
    "SmartCam": ["mqtt", "tcp", "udp"],
    "Thermostat": ["mqtt", "coap"],
    "DoorSensor": ["coap", "udp"],
    "WeatherNode": ["udp", "coap"],
    "SmartPlug": ["mqtt", "http"],
    "SmartLight": ["mqtt", "http"],
    "IndustrialSensor": ["mqtt", "udp"],
    "DoorLock": ["coap", "http"]
}

dest_ports_common = [80, 443, 1883, 5683, 502]  # include modbus 502 for industrial

attack_patterns = ["normal", "DoS", "DataExfil", "Spoofing", "Scan"]

rows = []

def rand_ip():
    # generate random private IPv4
    return str(ipaddress.IPv4Address(random.randint(int(ipaddress.IPv4Address("10.0.0.0")),
                                                    int(ipaddress.IPv4Address("10.255.255.255")))))

for device_id in range(1, NUM_DEVICES + 1):
    dtype = random.choice(device_types)
    proto_choices = protocols_by_device.get(dtype, ["mqtt","udp"])
    base_time = START_TIME + timedelta(seconds=random.randint(0, 300))
    # base behavior parameters vary by device type
    if dtype in ["SmartCam", "IndustrialSensor"]:
        base_packet_rate = random.randint(120, 400)
        base_byte_rate = random.randint(2000, 8000)
    elif dtype in ["Thermostat", "SmartPlug", "SmartLight"]:
        base_packet_rate = random.randint(20, 120)
        base_byte_rate = random.randint(200, 2000)
    else:
        base_packet_rate = random.randint(30, 180)
        base_byte_rate = random.randint(500, 3000)

    # device IPs and ports
    src_ip = rand_ip()
    dst_ip = "192.168.1.1"
    src_port_base = random.randint(20000, 40000)

    # simulate sequence of records for device
    current_time = base_time
    for rec in range(RECORDS_PER_DEVICE):
        # often normal, sometimes attack
        attack_roll = random.random()
        if attack_roll < 0.90:
            attack = "normal"
        else:
            attack = random.choices(attack_patterns[1:], weights=[0.5,0.3,0.1,0.1])[0]

        # tweak values based on attack
        if attack == "normal":
            packet_rate = int(random.gauss(base_packet_rate, base_packet_rate*0.15))
            byte_rate = int(random.gauss(base_byte_rate, base_byte_rate*0.20))
            duration = round(random.uniform(0.2, 6.0), 2)
        elif attack == "DoS":
            # bursts
            packet_rate = random.randint(int(base_packet_rate*3), int(base_packet_rate*8))
            byte_rate = random.randint(int(base_byte_rate*3), int(base_byte_rate*10))
            duration = round(random.uniform(1.0, 60.0), 2)
        elif attack == "DataExfil":
            packet_rate = random.randint(int(base_packet_rate*1.2), int(base_packet_rate*3))
            byte_rate = random.randint(int(base_byte_rate*4), int(base_byte_rate*20))
            duration = round(random.uniform(20.0, 300.0), 2)
        elif attack == "Spoofing":
            # inconsistent protocol/port combos
            packet_rate = int(random.gauss(base_packet_rate*1.1, base_packet_rate*0.3))
            byte_rate = int(random.gauss(base_byte_rate*1.2, base_byte_rate*0.3))
            duration = round(random.uniform(0.1, 15.0), 2)
        else:  # Scan
            packet_rate = random.randint(5, 200)
            byte_rate = random.randint(200, 2000)
            duration = round(random.uniform(0.05, 2.0), 2)

        # choose protocol (attack can force odd protocol)
        if attack == "Spoofing":
            protocol = random.choice(["http", "udp", "mqtt"])  # random mismatch
        else:
            protocol = random.choice(proto_choices)

        src_port = src_port_base + (rec % 500)
        dst_port = random.choice(dest_ports_common)

        # derived features
        packet_size = round(byte_rate / max(1, packet_rate), 2)  # avg bytes per packet
        is_attack_label = "Attack" if attack != "normal" else "Normal"

        rows.append({
            "timestamp": (current_time + timedelta(seconds=rec * TIME_STEP_SECONDS)).strftime("%Y-%m-%d %H:%M:%S"),
            "device_id": f"dev_{device_id:03d}",
            "device_type": dtype,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "source_port": int(src_port),
            "destination_port": int(dst_port),
            "packet_rate": int(max(0, packet_rate)),
            "byte_rate": int(max(0, byte_rate)),
            "packet_size": float(max(1.0, packet_size)),
            "connection_duration": duration,
            "attack_type": attack,
            "label": is_attack_label
        })

# shuffle for variety
random.shuffle(rows)

df = pd.DataFrame(rows)
out_path = "dataset/iot_data_realistic.csv"
df.to_csv(out_path, index=False)
print("✅ Saved realistic dataset to", out_path)
print("Shape:", df.shape)
print(df.head(10).to_string(index=False))
