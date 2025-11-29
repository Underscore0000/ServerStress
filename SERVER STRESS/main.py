#!/usr/bin/env python3
import os
import sys
import signal
from colorama import init, Fore, Back, Style
from modules.attack_tools import AttackTools
from modules.network_analysis import NetworkAnalysis
from modules.server_benchmark import ServerBenchmark
from modules.security_tools import SecurityTools
from utils.graphics import Graphics

# Initialize colorama
init(autoreset=True)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

BANNER = f"""{Colors.RED}
╔════════════════════════════════════════════════════════════════════════════════════════════════════════════╗                              
║                                                                                                            ║
║                                                                                                            ║
║ ██████ ▓█████  ██▀███   ██▒   █▓▓█████  ██▀███       ██████ ▄▄▄█████▓ ██▀███  ▓█████   ██████   ██████     ║
║▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒   ▒██    ▒ ▓  ██▒ ▓▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▒██    ▒    ║
║░ ▓██▄   ▒███   ▓██ ░▄█ ▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒   ░ ▓██▄   ▒ ▓██░ ▒░▓██ ░▄█ ▒▒███   ░ ▓██▄   ░ ▓██▄      ║
║ ▒   ██▒▒▓█  ▄ ▒██▀▀█▄    ▒██ █░░▒▓█  ▄ ▒██▀▀█▄       ▒   ██▒░ ▓██▓ ░ ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒  ▒   ██▒    ║
║▒██████▒▒░▒████▒░██▓ ▒██▒   ▒▀█░  ░▒████▒░██▓ ▒██▒   ▒██████▒▒  ▒██▒ ░ ░██▓ ▒██▒░▒████▒▒██████▒▒▒██████▒▒   ║
║▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░   ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░   ▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░   ║
║░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░   ░ ░▒  ░ ░    ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░   ║
║░  ░  ░     ░     ░░   ░      ░░     ░     ░░   ░    ░  ░  ░    ░        ░░   ░    ░   ░  ░  ░  ░  ░  ░     ║
║      ░     ░  ░   ░           ░     ░  ░   ░              ░              ░        ░  ░      ░        ░     ║
║                              ░                                                                             ║
║                                                                                                            ║
║                          {Colors.GREEN}made by Underscore000_{Colors.RED}                                                            ║
║                                                                                                            ║                                                                           
╚════════════════════════════════════════════════════════════════════════════════════════════════════════════╝                             
{Colors.RESET}"""

MENU = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.YELLOW}                       STRESS NETWORK SUITE v1.0{Colors.CYAN}               ║
╠════════════════════╦════════════════════════╦══════════════════════╦═══════════════════╣
║ {Colors.WHITE}  ATTACK TOOLS     {Colors.CYAN}║{Colors.WHITE}    NETWORK ANALYSIS    {Colors.CYAN}║{Colors.WHITE}    SERVER BENCHMARK  {Colors.CYAN}║{Colors.WHITE}     SECURITY      {Colors.CYAN}║
╠════════════════════╬════════════════════════╬══════════════════════╬═══════════════════╣
║ 01 HTTP Flood      ║ 11 Port Scanner        ║ 21 Concurrent Users  ║ 31 Vuln Scanner   ║
║ 02 TCP/UDP Flood   ║ 12 Network Latency     ║ 22 Database Load     ║ 32 SSL Analyzer   ║
║ 03 Slowloris       ║ 13 Bandwidth Monitor   ║ 23 API Tester        ║ 33 CORS Tester    ║
║ 04 DNSAmplification║ 14 Packet Sniffer      ║ 24 WebSocket Test    ║ 34 Header Check   ║
║ 05 SSL Stress Test ║ 15 Traceroute Plus     ║ 25 Resource Monitor  ║ 35 Brute Force    ║
║ 06 ICMP Flood      ║ 16 Ping Sweep          ║ 26 Cache Stress      ║ 36 SecurityHeaders║
║ 07 HTTP/2 Attack   ║ 17 Network Discovery   ║ 27 File I/O Test     ║ 37 SQL Injection  ║
║ 08 SMTP Flood      ║ 18 DNS Query Test      ║ 28 Memory Leak Test  ║ 38 XSS Tester     ║
║ 09 SIP Flood       ║ 19 HTTP Header Check   ║ 29 Load Balancer Test║ 39 CSRF Tester    ║
║ 10 RUDY Attack     ║ 20 SSL/TLS Scanner     ║ 30 Session Stress    ║ 40 Dir Bruteforce ║
╠════════════════════╩════════════════════════╩══════════════════════╩═══════════════════╣
║{Colors.RED}                                     00 EXIT{Colors.CYAN}                        ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""

class StressNetworkSuite:
    def __init__(self):
        self.graphics = Graphics()
        self.attack = AttackTools(self.graphics)
        self.network = NetworkAnalysis(self.graphics)
        self.benchmark = ServerBenchmark(self.graphics)
        self.security = SecurityTools(self.graphics)
        
        
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}Shutting down gracefully...{Colors.RESET}")
        sys.exit(0)
    
    def display_menu(self):
        self.graphics.clear_screen()
        print(BANNER)
        print(MENU)
    
    def get_target(self, tool_name):
        print(f"\n{Colors.CYAN}┌{'─'*60}┐")
        print(f"{Colors.CYAN}│{Colors.YELLOW} {tool_name:^58} {Colors.CYAN}│")
        print(f"{Colors.CYAN}└{'─'*60}┘{Colors.RESET}")
        target = input(f"{Colors.GREEN}🎯 Enter target IP/URL: {Colors.RESET}").strip()
        return target
    
    def run_tool(self, choice):
        tool_map = {
            # Attack Tools
            "01": ("HTTP Flood Attack", self.attack.http_flood),
            "02": ("TCP/UDP Flood Attack", self.attack.tcp_udp_flood),
            "03": ("Slowloris Attack", self.attack.slowloris),
            "04": ("DNS Amplification", self.attack.dns_amplification),
            "05": ("SSL Stress Test", self.attack.ssl_stress_test),
            "06": ("ICMP Flood", self.attack.icmp_flood),
            "07": ("HTTP/2 Attack", self.attack.http2_attack),
            "08": ("SMTP Flood", self.attack.smtp_flood),
            "09": ("SIP Flood", self.attack.sip_flood),
            "10": ("RUDY Attack", self.attack.rudy_attack),
            
            # Network Analysis
            "11": ("Port Scanner", self.network.port_scanner),
            "12": ("Network Latency", self.network.network_latency),
            "13": ("Bandwidth Monitor", self.network.bandwidth_monitor),
            "14": ("Packet Sniffer", self.network.packet_sniffer),
            "15": ("Traceroute Plus", self.network.traceroute_plus),
            "16": ("Ping Sweep", self.network.ping_sweep),
            "17": ("Network Discovery", self.network.network_discovery),
            "18": ("DNS Query Test", self.network.dns_query_test),
            "19": ("HTTP Header Check", self.network.http_header_check),
            "20": ("SSL/TLS Scanner", self.network.ssl_tls_scanner),
            
            # Server Benchmark
            "21": ("Concurrent Users", self.benchmark.concurrent_users),
            "22": ("Database Load Test", self.benchmark.database_load_test),
            "23": ("API Endpoint Tester", self.benchmark.api_endpoint_tester),
            "24": ("WebSocket Stress Test", self.benchmark.websocket_stress_test),
            "25": ("Resource Monitor", self.benchmark.resource_monitor),
            "26": ("Cache Stress Test", self.benchmark.cache_stress_test),
            "27": ("File I/O Test", self.benchmark.file_io_test),
            "28": ("Memory Leak Test", self.benchmark.memory_leak_test),
            "29": ("Load Balancer Test", self.benchmark.load_balancer_test),
            "30": ("Session Stress Test", self.benchmark.session_stress_test),
            
            # Security Tools
            "31": ("Vulnerability Scanner", self.security.vuln_scanner),
            "32": ("SSL Analyzer", self.security.ssl_analyzer),
            "33": ("CORS Tester", self.security.cors_tester),
            "34": ("HTTP Header Analyzer", self.security.http_header_analyzer),
            "35": ("Brute Force Tester", self.security.brute_force_tester),
            "36": ("Security Headers Check", self.security.security_headers_check),
            "37": ("SQL Injection Tester", self.security.sql_injection_tester),
            "38": ("XSS Tester", self.security.xss_tester),
            "39": ("CSRF Tester", self.security.csrf_tester),
            "40": ("Directory Bruteforce", self.security.directory_bruteforce)
        }
        
        if choice in tool_map:
            tool_name, tool_function = tool_map[choice]
            target = self.get_target(tool_name)
            
            try:
                tool_function(target)
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled by user{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            
            input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")
        else:
            print(f"{Colors.RED}Invalid tool selection!{Colors.RESET}")

    def main(self):
        while True:
            try:
                self.display_menu()
                choice = input(f"\n{Colors.GREEN}🔧 Select tool (00-40): {Colors.RESET}").strip()
                
                if choice == "00":
                    print(f"\n{Colors.GREEN}👋 Goodbye! Thanks for using Stress Network Suite{Colors.RESET}")
                    break
                elif choice.isdigit() and 1 <= int(choice) <= 40:
                    self.run_tool(choice.zfill(2))
                else:
                    print(f"{Colors.RED}❌ Invalid choice!{Colors.RESET}")
                    input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.GREEN}👋 Goodbye!{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}Unexpected error: {e}{Colors.RESET}")

if __name__ == "__main__":
    try:
        suite = StressNetworkSuite()
        suite.main()
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {e}{Colors.RESET}")