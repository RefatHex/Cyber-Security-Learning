import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 40
blocked_ips_time = {}
BLOCK_DURATION = 300
print(f"THRESHOLD: {THRESHOLD}")
    

def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    
    current_time=time.time()
    time_interval= current_time-start_time[0]
    unblock_old_ips()
    if time_interval >=1:
        for ip,count in packet_count.items():
            packet_rate= count / time_interval
            
            if packet_rate> THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)
                blocked_ips_time[ip]=current_time
                
        packet_count.clear()
        start_time[0]=current_time()
                
                
def unblock_old_ips():
    current = time.time()
    ips_to_remove = [ip for ip, block_time in blocked_ips_time.items() if current - block_time > BLOCK_DURATION]
    
    for ip in ips_to_remove:
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
        blocked_ips.remove(ip)
        del blocked_ips_time[ip]
    
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run as root.")
        sys.exit(1)
    packet_count = defaultdict(int)
    blocked_ips = set()
    start_time = [time.time()]
    
    print("Starting DoS attack detection...")
    sniff(filter="ip", prn=packet_callback)