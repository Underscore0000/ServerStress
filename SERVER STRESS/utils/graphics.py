import os
import time
import threading
try:
    from alive_progress import alive_bar
except ImportError:
    print("⚠️  alive-progress non installato. Usa: pip install alive-progress")
    
from colorama import Fore, Style, Back
import psutil

# Definisci la classe Colors all'inizio del file
class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

class Graphics:
    def __init__(self):
        self.colors = {
            'red': Colors.RED,
            'green': Colors.GREEN,
            'yellow': Colors.YELLOW,
            'blue': Colors.BLUE,
            'magenta': Colors.MAGENTA,
            'cyan': Colors.CYAN,
            'white': Colors.WHITE,
            'reset': Colors.RESET
        }
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self, text, color='red'):
        print(f"{self.colors[color]}{text}{self.colors['reset']}")
    
    def animated_loading(self, text, duration=3):
        try:
            with alive_bar(len(range(duration*10)), title=text, bar='classic', spinner='dots') as bar:
                for i in range(duration*10):
                    time.sleep(0.1)
                    bar()
        except:
            # Fallback se alive_progress non è disponibile
            print(f"{text}...")
            time.sleep(duration)
    
    def progress_bar(self, current, total, text="Progress", width=50):
        percent = current / total
        filled = int(width * percent)
        bar = '█' * filled + '░' * (width - filled)
        print(f"\r{text} |{bar}| {current}/{total} ({percent:.1%})", end='', flush=True)
    
    def live_stats_dashboard(self, stats_callback, update_interval=1):
        """Dashboard per statistiche in tempo reale"""
        try:
            while True:
                stats = stats_callback()
                self.clear_screen()
                print(f"{Colors.CYAN}╔{'═'*60}╗{Colors.RESET}")
                print(f"{Colors.CYAN}║{Colors.YELLOW}{'REAL-TIME STATISTICS':^60}{Colors.CYAN}║{Colors.RESET}")
                print(f"{Colors.CYAN}╠{'═'*60}╣{Colors.RESET}")
                
                for key, value in stats.items():
                    print(f"{Colors.CYAN}║{Colors.WHITE} {key:<25} {Colors.GREEN}{value:>32} {Colors.CYAN}║{Colors.RESET}")
                
                print(f"{Colors.CYAN}╚{'═'*60}╝{Colors.RESET}")
                print(f"\n{Colors.YELLOW}Press Ctrl+C to stop monitoring{Colors.RESET}")
                time.sleep(update_interval)
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}Monitoring stopped{Colors.RESET}")
    
    def network_traffic_graph(self, sent, received, width=40):
        """Grafico a barre per traffico di rete"""
        max_val = max(sent, received, 1)
        sent_bar = '█' * int((sent / max_val) * width)
        received_bar = '█' * int((received / max_val) * width)
        
        print(f"{Colors.RED}Sent:     |{sent_bar}{' '*(width-len(sent_bar))}| {sent} KB/s{Colors.RESET}")
        print(f"{Colors.GREEN}Received: |{received_bar}{' '*(width-len(received_bar))}| {received} KB/s{Colors.RESET}")
    
    def packet_visualization(self, packet_type, count, size=0):
        """Visualizzazione pacchetti in tempo reale"""
        symbols = {
            'tcp': '📦', 'udp': '📫', 'http': '🌐', 
            'icmp': '📡', 'dns': '📨', 'ssl': '🔒'
        }
        symbol = symbols.get(packet_type, '📊')
        print(f"\r{symbol} {packet_type.upper()}: {count:,} packets | Size: {size} MB", end='', flush=True)