from scapy.all import *

def packet_callback(packet):
    try:
        if packet.haslayer(IP):  # Only print summaries of IP packets
            print(f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}")
    except Exception as e:
        print(f"Error in packet_callback: {e}")

# Determine the network interface connected to your local Wi-Fi network
# Replace 'wlan0' with the name of your Wi-Fi interface
interface = 'Wi-Fi'

# Start sniffing all traffic on the Wi-Fi interface with a timeout of 10 seconds
packets = sniff(iface=interface, prn=packet_callback, timeout=10)

# Print the number of packets captured
print(f"Number of packets captured: {len(packets)}")
