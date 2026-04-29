from pathlib import Path
import sys
import csv
from datetime import datetime, timedelta, timezone
import time
from scapy.all import IP, UDP, send
from scapy.contrib.gtp import GTPHeader, GTPEchoRequest, Raw


# Path to the CSV in the same project folder
CSV_PATH = Path(__file__).parent / "data" / "gtpc2send.csv"

# Start the sequence in one minute. Modifiable.
future_base = datetime.now(timezone.utc) + timedelta(minutes=0)

entries = [
    {
        "timestamp": (future_base + timedelta(seconds=3)).isoformat(),
        "dst_ip": '127.0.0.1',
        "teid": 0x00000001,
        "payload": b'shh ./be_quiet.shh',
    },
    {
        "timestamp": (future_base + timedelta(seconds=6)).isoformat(),
        "dst_ip": '127.0.0.1',
        "teid": 0x00000002,
        "payload": b'run payload.exetra',
    },
    {
        "timestamp": (future_base + timedelta(seconds=9)).isoformat(),
        "dst_ip": '127.0.0.1',
        "teid": 0x00000003,
        "payload": b'sorry',
    },
]

def write_entries():
    count = len(entries)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["timestamp", "dst_ip", "teid", "payload_hex"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for entry in entries:
            payload_hex = entry["payload"].hex()
            writer.writerow({
                "timestamp": entry["timestamp"],
                "dst_ip": entry["dst_ip"],
                "teid": entry["teid"],
                "payload_hex": payload_hex,
            })

    print(f"Wrote {count} entries to {CSV_PATH}")


def read_entries():
    loaded = []
    with open(CSV_PATH, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            item = {
                "timestamp": row["timestamp"],
                "dst_ip": row["dst_ip"],
                "teid": int(row["teid"]),
                "payload_hex": row["payload_hex"],
            }
            loaded.append(item)

    count = len(loaded)
    print(f"Loaded {count} entries from CSV.")
    return loaded

# Filter entries
def filter_sequence(sequence):
    original_length = len(sequence)
    tempList = []
    curr_time = datetime.now(timezone.utc).isoformat()
    for i in range(len(sequence)):
        ts = sequence[i].get('timestamp')
        if ts in [None,'']:
            continue
        elif ts < curr_time:
            continue
        else:
            tempList.append(sequence[i])
    sequence = tempList
    sequence = sorted(sequence, key=lambda e: e['timestamp'])
    print(f"Filtered {original_length-len(sequence)} entries from the CSV.")
    return sequence

# Check to determine the appropriate network interface
def get_iface():
    if sys.platform.startswith("win"):
        return "Ethernet"
    elif sys.platform.startswith("linux"):
        return "eth0"
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")
    
def deliver_packets(sequence):
    print('dp_preloop')
    counter=1
    for message in sequence:
        print(f'dp_inloop {counter}')
        # Parse the scheduled timestamp from CSV (already in UTC)
        start_time = datetime.fromisoformat(message["timestamp"])
        start_time = start_time.astimezone(timezone.utc)

        # Construct the packet
        ip_addr = message["dst_ip"]
        end_id = message["teid"]
        payload = bytes.fromhex(message["payload_hex"])
        pkt = (
            IP(dst=ip_addr) /
            UDP(dport=2123) /
            GTPHeader(version=2, gtp_type=1, teid=end_id) /
            GTPEchoRequest() /
            Raw(load=payload)
        )

        # Sleep until that UTC time
        curr_time = datetime.now(timezone.utc)
        delay = (start_time - curr_time).total_seconds()
        if delay > 0:
            time.sleep(delay)

        #Sending the packet, commented out
        #send(pkt, iface=iface, verbose=0)
        #If not using get_iface, can assign iface explicitly if desired
        #send(pkt, verbose=0)
        
        # Print the scheduled timestamp and actual send time, both in UTC
        curr_time = datetime.now(timezone.utc)
        latency = curr_time - start_time
        print(f'GTP-C packet {counter} sent at: {curr_time}')
        print(f'Scheduled for: {message['timestamp']}')
        print(f'Latency: {latency}')
        counter = counter + 1

    print(f'Sequence Complete. Sent {len(sequence)} GTP-C packets.')

# Ensure data/gtpc2send.csv exists beforehand
write_entries()

#iface = get_iface(), unnecessary if not using deliver_packets(), assigning manually, or defaulting
sequence = read_entries()
sequence = filter_sequence(sequence)
deliver_packets(sequence)