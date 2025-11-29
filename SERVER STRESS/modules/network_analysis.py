import socket
import subprocess
import platform
import time
import threading
import psutil
import requests
import dns.resolver
import ssl
import json
from scapy.all import *
from scapy.layers.http import HTTPRequest
from utils.helpers import *
from utils.graphics import *

class NetworkAnalysis:
    def __init__(self, graphics):
        self.graphics = graphics
        self.stop_flags = {}

    def port_scanner(self, target):
        print(f"{Colors.CYAN}🔍 Starting Comprehensive Port Scan on {target}{Colors.RESET}")
        
        scan_type = input(f"{Colors.YELLOW}Scan type (quick/full/service, default quick): {Colors.RESET}") or "quick"
        
        if scan_type == "quick":
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
        elif scan_type == "service":
            ports = list(range(1, 1001))  
        else:  # full
            ports = list(range(1, 10001)) 
        
        open_ports = []
        stats = {'scanned': 0, 'open': 0, 'filtered': 0, 'closed': 0}
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                stats['scanned'] += 1
                
                if result == 0:
                    service = self.get_service_name(port)
                    banner = self.get_banner(target, port)
                    open_ports.append((port, service, banner))
                    stats['open'] += 1
                    status = f"{Colors.GREEN}OPEN{Colors.RESET}"
                else:
                    stats['closed'] += 1
                    status = f"{Colors.RED}CLOSED{Colors.RESET}"
                
                
                progress = (stats['scanned'] / len(ports)) * 100
                print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                      f"{Colors.GREEN}✅ Open: {stats['open']} | "
                      f"{Colors.RED}❌ Closed: {stats['closed']}{Colors.RESET}", end='')
                
            except Exception as e:
                stats['filtered'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Scanning {len(ports)} ports on {target}...{Colors.RESET}")
        print(f"{Colors.YELLOW}⏳ This may take a while...{Colors.RESET}")
        
        start_time = time.time()
        
        
        threads = []
        for port in ports:
            t = threading.Thread(target=scan_port, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
            
            
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        
        for t in threads:
            t.join()
        
        total_time = time.time() - start_time
        
        
        print(f"\n\n{Colors.GREEN}🎊 Port Scan Completed in {total_time:.2f}s!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Scan Summary:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Open ports: {stats['open']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Closed ports: {stats['closed']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}🛡️ Filtered ports: {stats['filtered']}{Colors.RESET}")
        
        if open_ports:
            print(f"\n{Colors.CYAN}🔓 Open Ports:{Colors.RESET}")
            print(f"{Colors.WHITE}{'Port':<8} {'Service':<15} {'Banner':<30}{Colors.RESET}")
            print(f"{Colors.CYAN}{'─'*60}{Colors.RESET}")
            for port, service, banner in sorted(open_ports):
                banner_display = banner[:27] + "..." if banner and len(banner) > 30 else banner
                print(f"{Colors.GREEN}{port:<8} {service:<15} {banner_display or '':<30}{Colors.RESET}")

    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 27017: "MongoDB"
        }
        return services.get(port, "Unknown")

    def get_banner(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            if port in [80, 443, 8080]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:
                sock.send(b"SYST\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-Client\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner.split('\n')[0] if banner else None
            
        except:
            return None

    def network_latency(self, target):
        print(f"{Colors.CYAN}📡 Testing Network Latency to {target}{Colors.RESET}")
        
        count = int(input(f"{Colors.YELLOW}Number of pings (default 20): {Colors.RESET}") or 20)
        interval = float(input(f"{Colors.YELLOW}Interval between pings (default 0.5): {Colors.RESET}") or 0.5)
        
        latencies = []
        lost_packets = 0
        
        print(f"{Colors.MAGENTA}🎯 Starting latency test...{Colors.RESET}")
        
        for i in range(count):
            try:
                start_time = time.time()
                
                if platform.system().lower() == "windows":
                    param = "-n"
                else:
                    param = "-c"
                
                result = subprocess.run(
                    ["ping", param, "1", target],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if "time=" in line:
                            time_str = line.split('time=')[1].split(' ')[0]
                            latency = float(time_str.replace('ms', ''))
                            latencies.append(latency)
                            
                            # Real-time visualization
                            avg_latency = sum(latencies) / len(latencies)
                            max_latency = max(latencies)
                            min_latency = min(latencies)
                            
                            print(f"\r{Colors.GREEN}📊 Ping {i+1}/{count} | "
                                  f"{Colors.CYAN}⏱️ {latency:.1f}ms | "
                                  f"{Colors.YELLOW}📈 Avg: {avg_latency:.1f}ms | "
                                  f"{Colors.RED}📉 Min: {min_latency:.1f}ms | "
                                  f"{Colors.MAGENTA}📊 Max: {max_latency:.1f}ms{Colors.RESET}", end='')
                            break
                else:
                    lost_packets += 1
                    print(f"\r{Colors.RED}❌ Packet lost {i+1}/{count} | "
                          f"Lost: {lost_packets}{Colors.RESET}", end='')
                
            except subprocess.TimeoutExpired:
                lost_packets += 1
                print(f"\r{Colors.RED}⏰ Timeout {i+1}/{count} | "
                      f"Lost: {lost_packets}{Colors.RESET}", end='')
            except Exception as e:
                lost_packets += 1
                print(f"\r{Colors.RED}❌ Error {i+1}/{count} | "
                      f"Lost: {lost_packets}{Colors.RESET}", end='')
            
            time.sleep(interval)
        
        
        if latencies:
            packet_loss = (lost_packets / count) * 100
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            min_latency = min(latencies)
            jitter = sum(abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))) / (len(latencies) - 1)
            
            print(f"\n\n{Colors.GREEN}🎊 Latency Test Completed!{Colors.RESET}")
            print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
            print(f"  {Colors.GREEN}✅ Packets sent: {count}{Colors.RESET}")
            print(f"  {Colors.RED}❌ Packets lost: {lost_packets}{Colors.RESET}")
            print(f"  {Colors.YELLOW}📉 Packet loss: {packet_loss:.1f}%{Colors.RESET}")
            print(f"  {Colors.CYAN}⏱️ Average latency: {avg_latency:.1f}ms{Colors.RESET}")
            print(f"  {Colors.GREEN}📈 Minimum latency: {min_latency:.1f}ms{Colors.RESET}")
            print(f"  {Colors.RED}📊 Maximum latency: {max_latency:.1f}ms{Colors.RESET}")
            print(f"  {Colors.MAGENTA}📋 Jitter: {jitter:.1f}ms{Colors.RESET}")
            
            # Latency distribution visualization
            print(f"\n{Colors.CYAN}📈 Latency Distribution:{Colors.RESET}")
            ranges = [(0, 50), (50, 100), (100, 200), (200, 500), (500, float('inf'))]
            for range_min, range_max in ranges:
                count_in_range = len([l for l in latencies if range_min <= l < range_max])
                percentage = (count_in_range / len(latencies)) * 100
                bar = '█' * int(percentage / 2)
                print(f"  {Colors.WHITE}{range_min}-{range_max}ms: {bar} {percentage:.1f}%{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}❌ No successful pings! Target may be down.{Colors.RESET}")

    def bandwidth_monitor(self, target):
        print(f"{Colors.CYAN}📊 Starting Bandwidth Monitoring{Colors.RESET}")
        
        duration = int(input(f"{Colors.YELLOW}Monitoring duration seconds (default 60): {Colors.RESET}") or 60)
        interface = input(f"{Colors.YELLOW}Network interface (default all): {Colors.RESET}") or "all"
        
        stats_history = []
        stop_flag = threading.Event()
        
        def get_bandwidth_stats():
            net_io = psutil.net_io_counters(pernic=True)
            
            if interface != "all" and interface in net_io:
                stats = net_io[interface]
                return {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv
                }
            else:
                stats = psutil.net_io_counters()
                return {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv
                }
        
        initial_stats = get_bandwidth_stats()
        start_time = time.time()
        
        print(f"{Colors.MAGENTA}🎯 Monitoring bandwidth for {duration} seconds...{Colors.RESET}")
        print(f"{Colors.YELLOW}📈 Real-time bandwidth usage:{Colors.RESET}")
        
        try:
            while time.time() - start_time < duration and not stop_flag.is_set():
                time.sleep(1)
                current_stats = get_bandwidth_stats()
                elapsed = time.time() - start_time
                
                # Calculate rates
                sent_rate = (current_stats['bytes_sent'] - initial_stats['bytes_sent']) / elapsed
                recv_rate = (current_stats['bytes_recv'] - initial_stats['bytes_recv']) / elapsed
                
                sent_kbps = sent_rate / 1024
                recv_kbps = recv_rate / 1024
                
                # Store for history
                stats_history.append({
                    'time': elapsed,
                    'sent_kbps': sent_kbps,
                    'recv_kbps': recv_kbps
                })
                
                # Real-time visualization
                self.graphics.network_traffic_graph(sent_kbps, recv_kbps)
                
                print(f" {Colors.GREEN}↑ {sent_kbps:6.1f} KB/s{Colors.RESET} | "
                      f"{Colors.BLUE}↓ {recv_kbps:6.1f} KB/s{Colors.RESET} | "
                      f"{Colors.YELLOW}⏱️ {elapsed:5.1f}s{Colors.RESET}", end='\r')
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Bandwidth monitoring stopped{Colors.RESET}")
            stop_flag.set()
        
        # Final statistics
        if stats_history:
            avg_sent = sum(s['sent_kbps'] for s in stats_history) / len(stats_history)
            avg_recv = sum(s['recv_kbps'] for s in stats_history) / len(stats_history)
            max_sent = max(s['sent_kbps'] for s in stats_history)
            max_recv = max(s['recv_kbps'] for s in stats_history)
            
            print(f"\n\n{Colors.GREEN}🎊 Bandwidth Monitoring Completed!{Colors.RESET}")
            print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
            print(f"  {Colors.GREEN}📤 Average upload: {avg_sent:.1f} KB/s{Colors.RESET}")
            print(f"  {Colors.BLUE}📥 Average download: {avg_recv:.1f} KB/s{Colors.RESET}")
            print(f"  {Colors.RED}📈 Peak upload: {max_sent:.1f} KB/s{Colors.RESET}")
            print(f"  {Colors.MAGENTA}📊 Peak download: {max_recv:.1f} KB/s{Colors.RESET}")
            print(f"  {Colors.YELLOW}⏱️ Monitoring duration: {duration}s{Colors.RESET}")

    def packet_sniffer(self, target):
        print(f"{Colors.CYAN}📡 Starting Packet Sniffer{Colors.RESET}")
        
        duration = int(input(f"{Colors.YELLOW}Sniffing duration seconds (default 30): {Colors.RESET}") or 30)
        count = int(input(f"{Colors.YELLOW}Max packets to capture (default 100): {Colors.RESET}") or 100)
        
        packets_captured = []
        stats = {'tcp': 0, 'udp': 0, 'icmp': 0, 'http': 0, 'dns': 0, 'other': 0}
        
        def packet_handler(packet):
            if len(packets_captured) >= count:
                return
            
            packets_captured.append(packet)
            
            # Analyze packet type
            if packet.haslayer(TCP):
                stats['tcp'] += 1
                if packet.haslayer(HTTPRequest):
                    stats['http'] += 1
            elif packet.haslayer(UDP):
                stats['udp'] += 1
                if packet.haslayer(DNS):
                    stats['dns'] += 1
            elif packet.haslayer(ICMP):
                stats['icmp'] += 1
            else:
                stats['other'] += 1
            
            
            total = sum(stats.values())
            print(f"\r{Colors.GREEN}📦 Captured: {len(packets_captured)}/{count} | "
                  f"{Colors.CYAN}TCP: {stats['tcp']} | "
                  f"{Colors.BLUE}UDP: {stats['udp']} | "
                  f"{Colors.YELLOW}HTTP: {stats['http']} | "
                  f"{Colors.MAGENTA}DNS: {stats['dns']}{Colors.RESET}", end='')
        
        print(f"{Colors.MAGENTA}🎯 Starting packet capture for {duration} seconds...{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  Requires root privileges on Linux/Mac{Colors.RESET}")
        
        try:
            
            stop_sniff = threading.Event()
            
            def sniff_thread():
                sniff(prn=packet_handler, store=0, timeout=duration, stop_filter=lambda x: stop_sniff.is_set())
            
            sniffer = threading.Thread(target=sniff_thread)
            sniffer.daemon = True
            sniffer.start()
            
            
            start_time = time.time()
            while time.time() - start_time < duration and sniffer.is_alive():
                time.sleep(0.1)
            
            stop_sniff.set()
            sniffer.join(timeout=1)
            
        except Exception as e:
            print(f"\n{Colors.RED}❌ Packet sniffing failed: {e}{Colors.RESET}")
            return
        
        
        print(f"\n\n{Colors.GREEN}🎊 Packet Capture Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Capture Statistics:{Colors.RESET}")
        total_packets = sum(stats.values())
        for protocol, count in stats.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            bar = '█' * int(percentage / 5)
            print(f"  {Colors.WHITE}{protocol.upper():<6}: {bar} {count} packets ({percentage:.1f}%){Colors.RESET}")
        
        if packets_captured:
            print(f"\n{Colors.CYAN}🔍 Sample Packets:{Colors.RESET}")
            for i, packet in enumerate(packets_captured[:5]):  
                summary = packet.summary()
                print(f"  {Colors.YELLOW}{i+1}. {summary}{Colors.RESET}")

    def traceroute_plus(self, target):
        print(f"{Colors.CYAN}🛣️ Starting Advanced Traceroute to {target}{Colors.RESET}")
        
        max_hops = int(input(f"{Colors.YELLOW}Max hops (default 30): {Colors.RESET}") or 30)
        timeout = int(input(f"{Colors.YELLOW}Timeout per hop (default 1): {Colors.RESET}") or 1)
        
        hops = []
        stats = {'reached': False, 'total_hops': 0, 'timeouts': 0}
        
        print(f"{Colors.MAGENTA}🎯 Tracing route to {target}...{Colors.RESET}")
        
        for ttl in range(1, max_hops + 1):
            try:
                
                start_time = time.time()
                
                if platform.system().lower() == "windows":
                    result = subprocess.run(
                        ["tracert", "-d", "-h", str(ttl), "-w", str(timeout * 1000), target],
                        capture_output=True,
                        text=True,
                        timeout=timeout * 3
                    )
                else:
                    result = subprocess.run(
                        ["traceroute", "-n", "-q", "1", "-w", str(timeout), "-m", str(ttl), target],
                        capture_output=True,
                        text=True,
                        timeout=timeout * 3
                    )
                
               
                lines = result.stdout.split('\n')
                for line in lines:
                    if target in line or "reached" in line.lower():
                        stats['reached'] = True
                        break
                
               
                hop_time = (time.time() - start_time) * 1000
                hops.append({'hop': ttl, 'time': hop_time})
                
                print(f"\r{Colors.GREEN}🔍 Hop {ttl}: {hop_time:.1f}ms{Colors.RESET}", end='')
                
                if stats['reached']:
                    break
                    
            except subprocess.TimeoutExpired:
                stats['timeouts'] += 1
                print(f"\r{Colors.RED}⏰ Hop {ttl}: Timeout{Colors.RESET}", end='')
                hops.append({'hop': ttl, 'time': None})
            except Exception as e:
                print(f"\r{Colors.RED}❌ Hop {ttl}: Error{Colors.RESET}", end='')
                hops.append({'hop': ttl, 'time': None})
        
        stats['total_hops'] = len([h for h in hops if h['time'] is not None])
        
        print(f"\n\n{Colors.GREEN}🎊 Traceroute Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Route Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Target reached: {'Yes' if stats['reached'] else 'No'}{Colors.RESET}")
        print(f"  {Colors.BLUE}🛣️ Total hops: {stats['total_hops']}{Colors.RESET}")
        print(f"  {Colors.RED}⏰ Timeouts: {stats['timeouts']}{Colors.RESET}")
        
        if hops:
            print(f"\n{Colors.CYAN}📋 Hop Details:{Colors.RESET}")
            for hop in hops[:10]:  
                if hop['time'] is not None:
                    print(f"  {Colors.GREEN}Hop {hop['hop']}: {hop['time']:.1f}ms{Colors.RESET}")
                else:
                    print(f"  {Colors.RED}Hop {hop['hop']}: ***{Colors.RESET}")

    def ping_sweep(self, target):
        print(f"{Colors.CYAN}🌐 Starting Ping Sweep on Network{Colors.RESET}")
        
        network = input(f"{Colors.YELLOW}Network (e.g., 192.168.1.0/24): {Colors.RESET}") or target
        
        
        if '/' not in network:
            parts = network.split('.')
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        
        active_hosts = []
        stats = {'scanned': 0, 'active': 0, 'inactive': 0}
        
        def ping_host(ip):
            try:
                if platform.system().lower() == "windows":
                    param = "-n"
                else:
                    param = "-c"
                
                result = subprocess.run(
                    ["ping", param, "1", "-W", "1", ip],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                stats['scanned'] += 1
                
                if result.returncode == 0:
                    active_hosts.append(ip)
                    stats['active'] += 1
                    status = f"{Colors.GREEN}ACTIVE{Colors.RESET}"
                else:
                    stats['inactive'] += 1
                    status = f"{Colors.RED}INACTIVE{Colors.RESET}"
                
                progress = (stats['scanned'] / 254) * 100
                print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                      f"{Colors.GREEN}✅ Active: {stats['active']} | "
                      f"{Colors.RED}❌ Inactive: {stats['inactive']}{Colors.RESET}", end='')
                
            except:
                stats['inactive'] += 1
                stats['scanned'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Scanning network {network}...{Colors.RESET}")
        
        
        base_ip = network.split('/')[0]
        base_parts = base_ip.split('.')
        
        threads = []
        for i in range(1, 255):  # Skip .0 and .255
            ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)
            
            
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
       
        for t in threads:
            t.join()
        
        print(f"\n\n{Colors.GREEN}🎊 Ping Sweep Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Scan Results:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Active hosts: {stats['active']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Inactive hosts: {stats['inactive']}{Colors.RESET}")
        
        if active_hosts:
            print(f"\n{Colors.CYAN}🔍 Active Hosts:{Colors.RESET}")
            for i, host in enumerate(sorted(active_hosts)):
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except:
                    hostname = "Unknown"
                print(f"  {Colors.GREEN}{host:<15} -> {hostname}{Colors.RESET}")

    def network_discovery(self, target):
        print(f"{Colors.CYAN}🔎 Starting Network Discovery{Colors.RESET}")
        
        print(f"{Colors.MAGENTA}🎯 Discovering network information for {target}...{Colors.RESET}")
        
        discovery_info = {}
        
        try:
           
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            discovery_info['local_machine'] = {
                'hostname': hostname,
                'ip_address': local_ip
            }
            
           
            interfaces = psutil.net_if_addrs()
            discovery_info['network_interfaces'] = {}
            
            for interface, addrs in interfaces.items():
                discovery_info['network_interfaces'][interface] = []
                for addr in addrs:
                    discovery_info['network_interfaces'][interface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
            
            try:
                target_ip = socket.gethostbyname(target)
                discovery_info['target'] = {
                    'hostname': target,
                    'ip_address': target_ip
                }
                
                
                try:
                    target_hostname = socket.gethostbyaddr(target_ip)[0]
                    discovery_info['target']['reverse_dns'] = target_hostname
                except:
                    discovery_info['target']['reverse_dns'] = "Not found"
                    
            except:
                discovery_info['target'] = {'error': 'Could not resolve target'}
            
         
            if platform.system().lower() != "windows":
                try:
                    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "default" in line:
                            discovery_info['gateway'] = line.split()[2]
                            break
                except:
                    pass
            
            
            print(f"\n{Colors.GREEN}🎊 Network Discovery Completed!{Colors.RESET}")
            
            print(f"\n{Colors.CYAN}💻 Local Machine:{Colors.RESET}")
            print(f"  {Colors.GREEN}Hostname: {discovery_info['local_machine']['hostname']}{Colors.RESET}")
            print(f"  {Colors.BLUE}IP Address: {discovery_info['local_machine']['ip_address']}{Colors.RESET}")
            
            print(f"\n{Colors.CYAN}🎯 Target Information:{Colors.RESET}")
            if 'error' not in discovery_info['target']:
                print(f"  {Colors.GREEN}Hostname: {discovery_info['target']['hostname']}{Colors.RESET}")
                print(f"  {Colors.BLUE}IP Address: {discovery_info['target']['ip_address']}{Colors.RESET}")
                print(f"  {Colors.YELLOW}Reverse DNS: {discovery_info['target']['reverse_dns']}{Colors.RESET}")
            else:
                print(f"  {Colors.RED}Error: {discovery_info['target']['error']}{Colors.RESET}")
            
            print(f"\n{Colors.CYAN}🔌 Network Interfaces:{Colors.RESET}")
            for interface, addrs in discovery_info['network_interfaces'].items():
                print(f"  {Colors.MAGENTA}{interface}:{Colors.RESET}")
                for addr in addrs[:2]:  
                    print(f"    {Colors.WHITE}{addr['family']}: {addr['address']}{Colors.RESET}")
            
            if 'gateway' in discovery_info:
                print(f"\n{Colors.CYAN}🌐 Default Gateway:{Colors.RESET}")
                print(f"  {Colors.GREEN}{discovery_info['gateway']}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}❌ Network discovery failed: {e}{Colors.RESET}")

    def dns_query_test(self, target):
        print(f"{Colors.CYAN}📨 Starting DNS Query Test for {target}{Colors.RESET}")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        
        results = {}
        
        print(f"{Colors.MAGENTA}🎯 Testing DNS records for {target}...{Colors.RESET}")
        
        for record_type in record_types:
            try:
                print(f"\r{Colors.CYAN}🔍 Querying {record_type} records...{Colors.RESET}", end='')
                
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns.resolver.Resolver().nameservers[0]]  
                
                answers = resolver.resolve(target, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
                
            except dns.resolver.NoAnswer:
                results[record_type] = ["No records found"]
            except dns.resolver.NXDOMAIN:
                results[record_type] = ["Domain does not exist"]
            except Exception as e:
                results[record_type] = [f"Error: {str(e)}"]
        
        print(f"\n\n{Colors.GREEN}🎊 DNS Query Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 DNS Records for {target}:{Colors.RESET}")
        
        for record_type, records in results.items():
            print(f"\n{Colors.MAGENTA}{record_type} Records:{Colors.RESET}")
            for record in records:
                print(f"  {Colors.GREEN}{record}{Colors.RESET}")

    def http_header_check(self, target):
        print(f"{Colors.CYAN}🔍 Analyzing HTTP Headers for {target}{Colors.RESET}")
        
        protocols = ['http', 'https']
        results = {}
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{target}"
                print(f"\r{Colors.CYAN}🔍 Checking {url}...{Colors.RESET}", end='')
                
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                results[protocol] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'final_url': response.url,
                    'redirects': len(response.history)
                }
                
            except Exception as e:
                results[protocol] = {'error': str(e)}
        
        print(f"\n\n{Colors.GREEN}🎊 HTTP Header Analysis Completed!{Colors.RESET}")
        
        for protocol, result in results.items():
            url = f"{protocol}://{target}"
            print(f"\n{Colors.CYAN}🔗 {url.upper()}:{Colors.RESET}")
            
            if 'error' in result:
                print(f"  {Colors.RED}Error: {result['error']}{Colors.RESET}")
            else:
                print(f"  {Colors.GREEN}Status: {result['status_code']}{Colors.RESET}")
                print(f"  {Colors.BLUE}Final URL: {result['final_url']}{Colors.RESET}")
                print(f"  {Colors.YELLOW}Redirects: {result['redirects']}{Colors.RESET}")
                
                print(f"\n  {Colors.MAGENTA}Headers:{Colors.RESET}")
                for header, value in result['headers'].items():
                    if any(security_header in header.lower() for security_header in 
                          ['server', 'x-powered-by', 'x-frame-options', 'content-security-policy']):
                        color = Colors.GREEN
                    else:
                        color = Colors.WHITE
                    print(f"    {color}{header}: {value}{Colors.RESET}")

    def ssl_tls_scanner(self, target):
        print(f"{Colors.CYAN}🔐 Starting SSL/TLS Scanner for {target}{Colors.RESET}")
        
        try:
            context = ssl.create_default_context()
            
            print(f"{Colors.MAGENTA}🎯 Analyzing SSL/TLS configuration...{Colors.RESET}")
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Get certificate info
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'version': cert.get('version', 'Unknown')
                    }
                    
                    # Check certificate expiration
                    from datetime import datetime
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    print(f"\n{Colors.GREEN}🎊 SSL/TLS Scan Completed!{Colors.RESET}")
                    print(f"{Colors.CYAN}📊 SSL/TLS Information:{Colors.RESET}")
                    print(f"  {Colors.GREEN}🔒 Protocol: {version}{Colors.RESET}")
                    print(f"  {Colors.BLUE}🛡️ Cipher: {cipher[0]} ({cipher[1]} bits){Colors.RESET}")
                    
                    print(f"\n{Colors.CYAN}📜 Certificate Information:{Colors.RESET}")
                    print(f"  {Colors.GREEN}📝 Subject: {cert_info['subject']}{Colors.RESET}")
                    print(f"  {Colors.BLUE}🏢 Issuer: {cert_info['issuer']}{Colors.RESET}")
                    print(f"  {Colors.YELLOW}📅 Valid from: {cert_info['not_before']}{Colors.RESET}")
                    print(f"  {Colors.MAGENTA}📅 Valid until: {cert_info['not_after']}{Colors.RESET}")
                    
                    if days_until_expiry > 30:
                        print(f"  {Colors.GREEN}✅ Expires in: {days_until_expiry} days{Colors.RESET}")
                    elif days_until_expiry > 0:
                        print(f"  {Colors.YELLOW}⚠️ Expires in: {days_until_expiry} days{Colors.RESET}")
                    else:
                        print(f"  {Colors.RED}❌ Certificate expired!{Colors.RESET}")
                        
        except Exception as e:
            print(f"{Colors.RED}❌ SSL/TLS scan failed: {e}{Colors.RESET}")