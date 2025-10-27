import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
import statistics


#Statistical Anomaly Detection

THRESHOLD = 40
blocked_ips_time = {}
BLOCK_DURATION = 300
print(f"THRESHOLD: {THRESHOLD}")
    
def packet_callback(packet):
    src_ip = packet[IP].src
    current_time = time.time()
    time_interval = current_time - start_time[0]
    
    if time_interval >= 1:
        rates = []
        for ip, count in packet_count.items():
            rate = count / time_interval
            rates.append(rate)

        if len(rates) > 3: 
            mean_rate = statistics.mean(rates)
            stdev = statistics.stdev(rates)
            
            for ip, count in packet_count.items():
                rate = count / time_interval
                if (rate > mean_rate + (3 * stdev)) and ip not in blocked_ips:
                    print(f"Blocking IP: {ip}, anomaly detected! Rate: {rate:.2f} pps (mean: {mean_rate:.2f})")
                    os.system(f"iptables -A INPUT -s {ip} -j DROP")
                    blocked_ips.add(ip)
                    blocked_ips_time[ip] = current_time
        
        packet_count.clear()
        start_time[0] = current_time
        
        
        
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