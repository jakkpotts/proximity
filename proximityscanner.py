import os
import time
import requests
import asyncio
from bleak import BleakScanner
from bleak.exc import BleakDBusError
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text
from threading import Thread, Lock
import signal
import hashlib

# Explicit imports from Scapy
from scapy.layers.dot11 import Dot11
from scapy.all import sniff

# Dictionary to keep track of detected devices
# Format: {device_key: (vendor, rssi, distance, last_seen, detection_type)}
detected_devices = {}
detected_devices_lock = Lock()

# Cache for vendor lookups
vendor_cache = {}

# Time to consider a device "gone" if no packets have been seen in this period
TIMEOUT = 300  # 5 minutes

# Reference RSSI at 1 meter (you can tweak this based on the environment)
RSSI_REF = -41
# Path loss exponent (2-4), adjust depending on the environment
PATH_LOSS_EXPONENT = 2.3

# Create a console for rich
console = Console()

# API to perform MAC address lookup
def get_device_vendor(mac):
    if mac in vendor_cache:
        return vendor_cache[mac]  # Return cached vendor

    url = f"https://api.macvendors.com/{mac}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            vendor = response.text.strip()
        else:
            vendor = "Unknown Vendor"
    except Exception:
        vendor = "Unknown Vendor"

    vendor_cache[mac] = vendor  # Cache the result
    return vendor

# Estimate distance from RSSI value in feet
def estimate_distance(rssi, rssi_ref=RSSI_REF, n=PATH_LOSS_EXPONENT):
    distance_meters = 10 ** ((rssi_ref - rssi) / (10 * n))
    distance_feet = distance_meters * 3.28084  # Convert meters to feet
    return distance_feet

# Function to generate a device key using MAC and name/UUID (if available) and shorten the hash
def generate_device_key(mac, name):
    device_id = f"{mac}_{name}"
    # Generate SHA-256 hash and truncate it to the first 8 characters for brevity
    return hashlib.sha256(device_id.encode()).hexdigest()[:8]

# Packet handler for sniffing Wi-Fi packets
def packet_handler(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 4:
            client_mac = packet.addr2
            rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100
            distance = estimate_distance(rssi)
            vendor = get_device_vendor(client_mac)
            device_key = generate_device_key(client_mac, vendor)  # Use MAC and vendor as the key
            with detected_devices_lock:
                detected_devices[device_key] = (vendor, rssi, distance, time.time(), "Wi-Fi")

        elif packet.type == 2:
            client_mac = packet.addr2
            rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100
            distance = estimate_distance(rssi)
            vendor = get_device_vendor(client_mac)
            device_key = generate_device_key(client_mac, vendor)  # Use MAC and vendor as the key
            with detected_devices_lock:
                detected_devices[device_key] = (vendor, rssi, distance, time.time(), "Wi-Fi")

# Perform BLE scan and add detected devices
async def ble_scan():
    scanner = BleakScanner(detection_callback=handle_device)
    try:
        await scanner.start()
        await asyncio.sleep(10)
    except BleakDBusError as e:
        console.print(f"[red]BLE scan error: {e}[/red]")
        await reset_adapter()
    finally:
        await scanner.stop()

async def handle_device(device, advertisement_data):
    try:
        mac = device.address
        name = advertisement_data.local_name or "Unknown BLE Device"
        device_key = generate_device_key(mac, name)  # Generate a stable key using MAC and name

        rssi = advertisement_data.rssi
        distance = estimate_distance(rssi)

        with detected_devices_lock:
            detected_devices[device_key] = (name, rssi, distance, time.time(), "Bluetooth")
    except Exception as e:
        console.print(f"[red]Error handling device: {e}[/red]")

# Reset Bluetooth adapter
async def reset_adapter():
    os.system("sudo hciconfig hci0 down")
    os.system("sudo hciconfig hci0 up")
    os.system("sudo systemctl restart bluetooth")

# Create a table for detected devices
def create_table(devices):
    table = Table(title="Detected Devices")

    table.add_column("Device hash", style="cyan", no_wrap=True)
    table.add_column("Vendor/Name", style="yellow")
    table.add_column("RSSI (dBm)", justify="right", style="magenta")
    table.add_column("Distance (ft)", justify="right", style="green")
    table.add_column("Last Seen (Seconds Ago)", justify="right")
    table.add_column("Type", style="blue", no_wrap=True)

    current_time = time.time()
    with detected_devices_lock:
        # Sort devices by distance (least to greatest)
        sorted_devices = sorted(devices.items(), key=lambda item: item[1][2])  # item[1][2] is the distance
        
        for device_key, details in sorted_devices:
            vendor, rssi, distance, last_seen, detection_type = details
            time_ago = int(current_time - last_seen)
            
            # Format the distance value
            if distance <= 10:
                distance_display = Text(f"{distance:.2f}", style="white")
            elif distance <= 20:
                distance_display = Text(f"{distance:.2f}", style="red")
            elif distance <= 30:
                distance_display = Text(f"{distance:.2f}", style="bold yellow")
            else:
                distance_display = Text(f"{distance:.2f}", style="")

            # Set row style based on distance
            row_style = "bold white on red" if distance <= 10 else ""

            table.add_row(device_key, vendor, f"{rssi}", distance_display, f"{time_ago}", detection_type, style=row_style)
    return table

# Function to run sniffing in a separate thread
def start_sniffing(iface):
    sniff(iface=iface, prn=packet_handler, store=0)

# Function to start BLE scanning in a separate thread with its own event loop
async def start_ble_scanning():
    while True:
        scanner = BleakScanner(detection_callback=handle_device)
        try:
            await scanner.start()
            await asyncio.sleep(12)  # Scan for 12 seconds
        except BleakDBusError as e:
            console.print(f"[red]BLE scan error: {e}[/red]")
            await reset_adapter()
        finally:
            await scanner.stop()
        
        # Wait for 5 seconds before the next scan
        await asyncio.sleep(5)

# Signal handler for graceful exit
def handle_exit(signal_received, frame):
    asyncio.run(reset_adapter())
    exit(0)

# Register signal handlers for SIGINT (Ctrl+C) and SIGTERM
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

if __name__ == "__main__":
    # iface = input("Enter the network interface to use (e.g., wlan0): ")
    iface = "wlan1"
    console.print("[bold green]Sniffing for Wi-Fi and Bluetooth devices...[/bold green]")

    # Start Wi-Fi sniffing in a separate thread
    sniffing_thread = Thread(target=start_sniffing, args=(iface,))
    sniffing_thread.daemon = True
    sniffing_thread.start()

    # Start BLE scanning in a separate thread with its own event loop
    ble_thread = Thread(target=lambda: asyncio.run(start_ble_scanning()))
    ble_thread.daemon = True
    ble_thread.start()

    # Start the live table
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            # Update the live table
            live.update(create_table(detected_devices))

            # Remove old devices that haven't been seen in `TIMEOUT`
            current_time = time.time()
            with detected_devices_lock:
                detected_devices = {
                    device_key: details
                    for device_key, details in detected_devices.items()
                    if current_time - details[3] <= TIMEOUT
                }

            time.sleep(1)