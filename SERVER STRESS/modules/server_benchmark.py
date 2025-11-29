import threading
import time
import requests
import psutil
import random
import string
import json
import sqlite3
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import *
from utils.graphics import *

class ServerBenchmark:
    def __init__(self, graphics):
        self.graphics = graphics
        self.results = {}

    def concurrent_users(self, target):
        print(f"{Colors.CYAN}👥 Starting Concurrent Users Simulation on {target}{Colors.RESET}")
        
        users = int(input(f"{Colors.YELLOW}Number of concurrent users (default 50): {Colors.RESET}") or 50)
        duration = int(input(f"{Colors.YELLOW}Test duration seconds (default 60): {Colors.RESET}") or 60)
        endpoint = input(f"{Colors.YELLOW}Endpoint (default /): {Colors.RESET}") or "/"
        
        stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'response_times': [],
            'status_codes': {},
            'start_time': time.time()
        }
        
        stop_flag = threading.Event()
        lock = threading.Lock()
        
        def user_simulation(user_id):
            user_stats = {'requests': 0, 'success': 0, 'fail': 0}
            
            while not stop_flag.is_set() and (time.time() - stats['start_time']) < duration:
                try:
                    start_time = time.time()
                    
                    # Add some randomness to user behavior
                    time.sleep(random.uniform(0.1, 2.0))
                    
                    url = f"http://{target}{endpoint}"
                    response = requests.get(url, timeout=10)
                    response_time = (time.time() - start_time) * 1000  # Convert to ms
                    
                    with lock:
                        stats['total_requests'] += 1
                        stats['response_times'].append(response_time)
                        
                        if 200 <= response.status_code < 400:
                            stats['successful_requests'] += 1
                            user_stats['success'] += 1
                        else:
                            stats['failed_requests'] += 1
                            user_stats['fail'] += 1
                        
                        # Track status codes
                        status_code = response.status_code
                        stats['status_codes'][status_code] = stats['status_codes'].get(status_code, 0) + 1
                    
                    user_stats['requests'] += 1
                    
                    # Real-time display
                    elapsed = time.time() - stats['start_time']
                    rps = stats['total_requests'] / elapsed if elapsed > 0 else 0
                    success_rate = (stats['successful_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                    
                    print(f"\r{Colors.GREEN}👤 Users: {users} | "
                          f"{Colors.CYAN}📊 RPS: {rps:.1f} | "
                          f"{Colors.BLUE}✅ Success: {success_rate:.1f}% | "
                          f"{Colors.YELLOW}⏱️ Time: {elapsed:.1f}s/{duration}s{Colors.RESET}", end='')
                    
                except Exception as e:
                    with lock:
                        stats['failed_requests'] += 1
                        stats['total_requests'] += 1
                    user_stats['fail'] += 1
                    user_stats['requests'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Simulating {users} concurrent users for {duration} seconds...{Colors.RESET}")
        
        # Start user threads
        threads = []
        for i in range(users):
            t = threading.Thread(target=user_simulation, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Monitor progress
        try:
            while time.time() - stats['start_time'] < duration:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Test interrupted by user{Colors.RESET}")
        
        stop_flag.set()
        time.sleep(2)  # Give threads time to finish
        
        # Calculate final statistics
        total_time = time.time() - stats['start_time']
        avg_response_time = sum(stats['response_times']) / len(stats['response_times']) if stats['response_times'] else 0
        max_response_time = max(stats['response_times']) if stats['response_times'] else 0
        min_response_time = min(stats['response_times']) if stats['response_times'] else 0
        
        success_rate = (stats['successful_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
        rps = stats['total_requests'] / total_time if total_time > 0 else 0
        
        print(f"\n\n{Colors.GREEN}🎊 Concurrent Users Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Performance Summary:{Colors.RESET}")
        print(f"  {Colors.GREEN}👥 Concurrent Users: {users}{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️ Test Duration: {total_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.CYAN}📦 Total Requests: {stats['total_requests']:,}{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Successful: {stats['successful_requests']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Failed: {stats['failed_requests']:,}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📊 Success Rate: {success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Requests/Sec: {rps:.1f}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}⏱️ Response Times:{Colors.RESET}")
        print(f"  {Colors.GREEN}📈 Average: {avg_response_time:.2f}ms{Colors.RESET}")
        print(f"  {Colors.BLUE}📉 Minimum: {min_response_time:.2f}ms{Colors.RESET}")
        print(f"  {Colors.RED}📊 Maximum: {max_response_time:.2f}ms{Colors.RESET}")
        
        if stats['status_codes']:
            print(f"\n{Colors.CYAN}📋 HTTP Status Codes:{Colors.RESET}")
            for code, count in sorted(stats['status_codes'].items()):
                percentage = (count / stats['total_requests']) * 100
                color = Colors.GREEN if 200 <= code < 300 else Colors.YELLOW if 300 <= code < 400 else Colors.RED
                print(f"  {color}{code}: {count} ({percentage:.1f}%){Colors.RESET}")

    def database_load_test(self, target):
        print(f"{Colors.CYAN}🗄️ Starting Database Load Test{Colors.RESET}")
        
        # Create a test database
        db_file = "test_database.db"
        operations = int(input(f"{Colors.YELLOW}Number of operations (default 1000): {Colors.RESET}") or 1000)
        concurrent_threads = int(input(f"{Colors.YELLOW}Concurrent threads (default 10): {Colors.RESET}") or 10)
        
        # Initialize test database
        self._init_test_database(db_file)
        
        stats = {
            'operations_completed': 0,
            'operations_failed': 0,
            'select_times': [],
            'insert_times': [],
            'update_times': [],
            'delete_times': []
        }
        
        lock = threading.Lock()
        
        def database_operation(thread_id):
            local_stats = {'completed': 0, 'failed': 0}
            
            for i in range(operations // concurrent_threads):
                operation_type = random.choice(['select', 'insert', 'update', 'delete'])
                
                try:
                    start_time = time.time()
                    
                    if operation_type == 'select':
                        self._run_select_operation(db_file)
                        operation_time = time.time() - start_time
                        with lock:
                            stats['select_times'].append(operation_time)
                    elif operation_type == 'insert':
                        self._run_insert_operation(db_file)
                        operation_time = time.time() - start_time
                        with lock:
                            stats['insert_times'].append(operation_time)
                    elif operation_type == 'update':
                        self._run_update_operation(db_file)
                        operation_time = time.time() - start_time
                        with lock:
                            stats['update_times'].append(operation_time)
                    elif operation_type == 'delete':
                        self._run_delete_operation(db_file)
                        operation_time = time.time() - start_time
                        with lock:
                            stats['delete_times'].append(operation_time)
                    
                    with lock:
                        stats['operations_completed'] += 1
                    local_stats['completed'] += 1
                    
                except Exception as e:
                    with lock:
                        stats['operations_failed'] += 1
                    local_stats['failed'] += 1
                
                # Progress display
                progress = (stats['operations_completed'] + stats['operations_failed']) / operations * 100
                print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                      f"{Colors.GREEN}✅ Completed: {stats['operations_completed']} | "
                      f"{Colors.RED}❌ Failed: {stats['operations_failed']}{Colors.RESET}", end='')
        
        print(f"{Colors.MAGENTA}🎯 Running {operations} database operations with {concurrent_threads} threads...{Colors.RESET}")
        
        start_time = time.time()
        
        # Start database threads
        threads = []
        for i in range(concurrent_threads):
            t = threading.Thread(target=database_operation, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for completion
        for t in threads:
            t.join()
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        total_operations = stats['operations_completed'] + stats['operations_failed']
        success_rate = (stats['operations_completed'] / total_operations * 100) if total_operations > 0 else 0
        ops_per_second = stats['operations_completed'] / total_time if total_time > 0 else 0
        
        # Calculate average times per operation type
        avg_select = sum(stats['select_times']) / len(stats['select_times']) * 1000 if stats['select_times'] else 0
        avg_insert = sum(stats['insert_times']) / len(stats['insert_times']) * 1000 if stats['insert_times'] else 0
        avg_update = sum(stats['update_times']) / len(stats['update_times']) * 1000 if stats['update_times'] else 0
        avg_delete = sum(stats['delete_times']) / len(stats['delete_times']) * 1000 if stats['delete_times'] else 0
        
        print(f"\n\n{Colors.GREEN}🎊 Database Load Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Database Performance:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Operations Completed: {stats['operations_completed']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Operations Failed: {stats['operations_failed']:,}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📊 Success Rate: {success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Operations/Sec: {ops_per_second:.1f}{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️ Total Time: {total_time:.2f}s{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}⏱️ Operation Performance:{Colors.RESET}")
        print(f"  {Colors.GREEN}🔍 SELECT: {avg_select:.2f}ms avg ({len(stats['select_times'])} ops){Colors.RESET}")
        print(f"  {Colors.BLUE}📝 INSERT: {avg_insert:.2f}ms avg ({len(stats['insert_times'])} ops){Colors.RESET}")
        print(f"  {Colors.YELLOW}✏️ UPDATE: {avg_update:.2f}ms avg ({len(stats['update_times'])} ops){Colors.RESET}")
        print(f"  {Colors.RED}🗑️ DELETE: {avg_delete:.2f}ms avg ({len(stats['delete_times'])} ops){Colors.RESET}")
        
        # Cleanup
        try:
            os.remove(db_file)
        except:
            pass

    def _init_test_database(self, db_file):
        """Initialize test SQLite database"""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Create test table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_data (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT,
                age INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert some initial data
        for i in range(100):
            cursor.execute('''
                INSERT INTO test_data (name, email, age)
                VALUES (?, ?, ?)
            ''', (f"User_{i}", f"user_{i}@test.com", random.randint(18, 65)))
        
        conn.commit()
        conn.close()

    def _run_select_operation(self, db_file):
        """Run SELECT operation"""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM test_data WHERE age > ? LIMIT 10", (random.randint(18, 65),))
        results = cursor.fetchall()
        conn.close()
        return results

    def _run_insert_operation(self, db_file):
        """Run INSERT operation"""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO test_data (name, email, age)
            VALUES (?, ?, ?)
        ''', (f"Test_{random.randint(1000, 9999)}", f"test_{random.randint(1000, 9999)}@test.com", random.randint(18, 65)))
        conn.commit()
        conn.close()

    def _run_update_operation(self, db_file):
        """Run UPDATE operation"""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE test_data SET age = ? WHERE id = ?
        ''', (random.randint(18, 65), random.randint(1, 100)))
        conn.commit()
        conn.close()

    def _run_delete_operation(self, db_file):
        """Run DELETE operation"""
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Don't actually delete from original data, use a temp record
        cursor.execute("DELETE FROM test_data WHERE id > 100")
        conn.commit()
        conn.close()

    def api_endpoint_tester(self, target):
        print(f"{Colors.CYAN}🔧 Starting API Endpoint Tester for {target}{Colors.RESET}")
        
        # Common API endpoints to test
        api_endpoints = [
            "/api/v1/users",
            "/api/v1/products", 
            "/api/v1/orders",
            "/api/health",
            "/api/status",
            "/api/v1/config"
        ]
        
        results = {}
        stats = {'tested': 0, 'successful': 0, 'failed': 0}
        
        def test_endpoint(endpoint):
            try:
                url = f"http://{target}{endpoint}"
                start_time = time.time()
                
                response = requests.get(url, timeout=10, verify=False)
                response_time = (time.time() - start_time) * 1000
                
                result = {
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'success': 200 <= response.status_code < 400,
                    'headers': dict(response.headers),
                    'content_length': len(response.content)
                }
                
                # Try to parse JSON if possible
                try:
                    result['json_response'] = response.json()
                except:
                    result['text_preview'] = response.text[:100] + "..." if len(response.text) > 100 else response.text
                
                with lock:
                    stats['tested'] += 1
                    if result['success']:
                        stats['successful'] += 1
                    else:
                        stats['failed'] += 1
                
                return endpoint, result
                
            except Exception as e:
                result = {
                    'error': str(e),
                    'success': False,
                    'response_time': 0
                }
                with lock:
                    stats['tested'] += 1
                    stats['failed'] += 1
                return endpoint, result
        
        print(f"{Colors.MAGENTA}🎯 Testing {len(api_endpoints)} API endpoints...{Colors.RESET}")
        
        lock = threading.Lock()
        start_time = time.time()
        
        # Test endpoints concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_endpoint = {executor.submit(test_endpoint, endpoint): endpoint for endpoint in api_endpoints}
            
            for future in as_completed(future_to_endpoint):
                endpoint, result = future.result()
                results[endpoint] = result
                
                progress = (stats['tested'] / len(api_endpoints)) * 100
                success_rate = (stats['successful'] / stats['tested'] * 100) if stats['tested'] > 0 else 0
                
                print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                      f"{Colors.GREEN}✅ Successful: {stats['successful']} | "
                      f"{Colors.RED}❌ Failed: {stats['failed']} | "
                      f"{Colors.YELLOW}📈 Success Rate: {success_rate:.1f}%{Colors.RESET}", end='')
        
        total_time = time.time() - start_time
        
        print(f"\n\n{Colors.GREEN}🎊 API Endpoint Testing Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Test Summary:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Successful: {stats['successful']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Failed: {stats['failed']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📊 Success Rate: {success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️ Total Time: {total_time:.2f}s{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}🔍 Detailed Results:{Colors.RESET}")
        for endpoint, result in results.items():
            if result['success']:
                color = Colors.GREEN
                status = "✅"
            else:
                color = Colors.RED
                status = "❌"
            
            print(f"\n{color}{status} {endpoint}{Colors.RESET}")
            print(f"  {Colors.WHITE}Status: {result.get('status_code', 'N/A')} | "
                  f"Time: {result.get('response_time', 0):.2f}ms | "
                  f"Size: {result.get('content_length', 0)} bytes{Colors.RESET}")

    def websocket_stress_test(self, target):
        print(f"{Colors.CYAN}🔌 Starting WebSocket Stress Test{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  WebSocket testing requires websocket-client library{Colors.RESET}")
        
        try:
            import websocket
        except ImportError:
            print(f"{Colors.RED}❌ websocket-client not installed. Install with: pip install websocket-client{Colors.RESET}")
            return
        
        ws_url = input(f"{Colors.YELLOW}WebSocket URL (e.g., ws://echo.websocket.org): {Colors.RESET}") or "ws://echo.websocket.org"
        connections = int(input(f"{Colors.YELLOW}Number of concurrent connections (default 10): {Colors.RESET}") or 10)
        messages_per_connection = int(input(f"{Colors.YELLOW}Messages per connection (default 10): {Colors.RESET}") or 10)
        
        stats = {
            'connections_established': 0,
            'connections_failed': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'message_times': []
        }
        
        lock = threading.Lock()
        stop_flag = threading.Event()
        
        def websocket_client(client_id):
            try:
                ws = websocket.WebSocket()
                ws.connect(ws_url, timeout=10)
                
                with lock:
                    stats['connections_established'] += 1
                
                for i in range(messages_per_connection):
                    if stop_flag.is_set():
                        break
                    
                    message = f"Message {i} from client {client_id}"
                    start_time = time.time()
                    
                    ws.send(message)
                    with lock:
                        stats['messages_sent'] += 1
                    
                    # Try to receive echo
                    try:
                        response = ws.recv()
                        response_time = (time.time() - start_time) * 1000
                        
                        with lock:
                            stats['messages_received'] += 1
                            stats['message_times'].append(response_time)
                    except:
                        pass
                    
                    time.sleep(0.1)
                
                ws.close()
                
            except Exception as e:
                with lock:
                    stats['connections_failed'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Testing WebSocket with {connections} concurrent connections...{Colors.RESET}")
        
        start_time = time.time()
        
        # Start WebSocket clients
        threads = []
        for i in range(connections):
            t = threading.Thread(target=websocket_client, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Monitor progress
        try:
            while any(t.is_alive() for t in threads) and not stop_flag.is_set():
                time.sleep(0.5)
                
                established = stats['connections_established']
                failed = stats['connections_failed']
                total_connections = established + failed
                success_rate = (established / total_connections * 100) if total_connections > 0 else 0
                
                print(f"\r{Colors.CYAN}🔌 Connections: {established}/{connections} | "
                      f"{Colors.GREEN}✅ Success: {success_rate:.1f}% | "
                      f"{Colors.BLUE}📤 Sent: {stats['messages_sent']} | "
                      f"{Colors.YELLOW}📥 Received: {stats['messages_received']}{Colors.RESET}", end='')
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Test interrupted{Colors.RESET}")
            stop_flag.set()
        
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=1)
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        if stats['message_times']:
            avg_response_time = sum(stats['message_times']) / len(stats['message_times'])
            max_response_time = max(stats['message_times'])
            min_response_time = min(stats['message_times'])
        else:
            avg_response_time = max_response_time = min_response_time = 0
        
        message_success_rate = (stats['messages_received'] / stats['messages_sent'] * 100) if stats['messages_sent'] > 0 else 0
        
        print(f"\n\n{Colors.GREEN}🎊 WebSocket Stress Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 WebSocket Performance:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Connections Established: {stats['connections_established']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Connections Failed: {stats['connections_failed']}{Colors.RESET}")
        print(f"  {Colors.BLUE}📤 Messages Sent: {stats['messages_sent']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📥 Messages Received: {stats['messages_received']}{Colors.RESET}")
        print(f"  {Colors.MAGENTA}📊 Message Success Rate: {message_success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.CYAN}⏱️ Avg Response Time: {avg_response_time:.2f}ms{Colors.RESET}")
        print(f"  {Colors.GREEN}📈 Min Response Time: {min_response_time:.2f}ms{Colors.RESET}")
        print(f"  {Colors.RED}📊 Max Response Time: {max_response_time:.2f}ms{Colors.RESET}")

    def resource_monitor(self, target):
        print(f"{Colors.CYAN}📈 Starting Resource Monitoring{Colors.RESET}")
        
        duration = int(input(f"{Colors.YELLOW}Monitoring duration seconds (default 60): {Colors.RESET}") or 60)
        refresh_interval = float(input(f"{Colors.YELLOW}Refresh interval seconds (default 1): {Colors.RESET}") or 1)
        
        print(f"{Colors.MAGENTA}🎯 Monitoring system resources for {duration} seconds...{Colors.RESET}")
        
        # Data collection
        cpu_data = []
        memory_data = []
        disk_data = []
        network_data = []
        
        start_time = time.time()
        initial_net_io = psutil.net_io_counters()
        
        try:
            for i in range(int(duration / refresh_interval)):
                if time.time() - start_time >= duration:
                    break
                
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=refresh_interval)
                cpu_data.append(cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                memory_data.append(memory.percent)
                
                # Disk usage
                disk = psutil.disk_usage('/')
                disk_data.append(disk.percent)
                
                # Network usage
                net_io = psutil.net_io_counters()
                elapsed = time.time() - start_time
                sent_speed = (net_io.bytes_sent - initial_net_io.bytes_sent) / elapsed / 1024  # KB/s
                recv_speed = (net_io.bytes_recv - initial_net_io.bytes_recv) / elapsed / 1024  # KB/s
                network_data.append((sent_speed, recv_speed))
                
                # Real-time display
                elapsed_display = time.time() - start_time
                print(f"\r{Colors.GREEN}💻 CPU: {cpu_percent:5.1f}% | "
                      f"{Colors.BLUE}🧠 Memory: {memory.percent:5.1f}% | "
                      f"{Colors.YELLOW}💾 Disk: {disk.percent:5.1f}% | "
                      f"{Colors.CYAN}📤 Net Sent: {sent_speed:6.1f} KB/s | "
                      f"{Colors.MAGENTA}📥 Net Recv: {recv_speed:6.1f} KB/s | "
                      f"{Colors.WHITE}⏱️ Time: {elapsed_display:5.1f}s/{duration}s{Colors.RESET}", end='')
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Monitoring stopped{Colors.RESET}")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        avg_cpu = sum(cpu_data) / len(cpu_data) if cpu_data else 0
        max_cpu = max(cpu_data) if cpu_data else 0
        avg_memory = sum(memory_data) / len(memory_data) if memory_data else 0
        max_memory = max(memory_data) if memory_data else 0
        avg_disk = sum(disk_data) / len(disk_data) if disk_data else 0
        
        avg_sent_speed = sum(s[0] for s in network_data) / len(network_data) if network_data else 0
        avg_recv_speed = sum(s[1] for s in network_data) / len(network_data) if network_data else 0
        
        print(f"\n\n{Colors.GREEN}🎊 Resource Monitoring Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Resource Usage Summary:{Colors.RESET}")
        print(f"  {Colors.GREEN}💻 CPU Usage: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max{Colors.RESET}")
        print(f"  {Colors.BLUE}🧠 Memory Usage: {avg_memory:.1f}% avg, {max_memory:.1f}% max{Colors.RESET}")
        print(f"  {Colors.YELLOW}💾 Disk Usage: {avg_disk:.1f}% avg{Colors.RESET}")
        print(f"  {Colors.CYAN}📤 Network Sent: {avg_sent_speed:.1f} KB/s avg{Colors.RESET}")
        print(f"  {Colors.MAGENTA}📥 Network Received: {avg_recv_speed:.1f} KB/s avg{Colors.RESET}")
        print(f"  {Colors.WHITE}⏱️ Monitoring Duration: {total_time:.1f}s{Colors.RESET}")

    def cache_stress_test(self, target):
        print(f"{Colors.CYAN}⚡ Starting Cache Stress Test{Colors.RESET}")
        
        # This is a simulated cache test since we can't directly test external caches
        operations = int(input(f"{Colors.YELLOW}Number of cache operations (default 1000): {Colors.RESET}") or 1000)
        cache_size = int(input(f"{Colors.YELLOW}Simulated cache size (default 100): {Colors.RESET}") or 100)
        
        # Simulate cache behavior
        cache = {}
        stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'operations': 0,
            'hit_ratio': 0
        }
        
        print(f"{Colors.MAGENTA}🎯 Simulating cache with {cache_size} entries and {operations} operations...{Colors.RESET}")
        
        start_time = time.time()
        
        for i in range(operations):
            key = f"key_{random.randint(1, cache_size * 2)}"  # Some keys will be outside cache
            operation = random.choice(['get', 'set'])
            
            if operation == 'get':
                if key in cache:
                    stats['hits'] += 1
                    # Simulate cache hit - very fast
                    time.sleep(0.001)
                else:
                    stats['misses'] += 1
                    # Simulate cache miss - slower
                    time.sleep(0.01)
                    # Add to cache if we have space
                    if len(cache) < cache_size:
                        cache[key] = f"value_{i}"
                    else:
                        stats['evictions'] += 1
                        # Remove random item (simulate LRU)
                        if cache:
                            del cache[random.choice(list(cache.keys()))]
                        cache[key] = f"value_{i}"
            else:  # set operation
                if key in cache:
                    # Update existing
                    cache[key] = f"value_{i}"
                    time.sleep(0.001)
                else:
                    # Add new
                    if len(cache) >= cache_size:
                        stats['evictions'] += 1
                        if cache:
                            del cache[random.choice(list(cache.keys()))]
                    cache[key] = f"value_{i}"
                    time.sleep(0.002)
            
            stats['operations'] += 1
            
            # Progress display
            progress = (i + 1) / operations * 100
            hit_ratio = (stats['hits'] / (stats['hits'] + stats['misses'])) * 100 if (stats['hits'] + stats['misses']) > 0 else 0
            
            print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                  f"{Colors.GREEN}✅ Hits: {stats['hits']} | "
                  f"{Colors.RED}❌ Misses: {stats['misses']} | "
                  f"{Colors.YELLOW}📈 Hit Ratio: {hit_ratio:.1f}%{Colors.RESET}", end='')
        
        total_time = time.time() - start_time
        
        # Final statistics
        hit_ratio = (stats['hits'] / (stats['hits'] + stats['misses'])) * 100 if (stats['hits'] + stats['misses']) > 0 else 0
        ops_per_second = stats['operations'] / total_time
        
        print(f"\n\n{Colors.GREEN}🎊 Cache Stress Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Cache Performance:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Cache Hits: {stats['hits']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Cache Misses: {stats['misses']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📈 Hit Ratio: {hit_ratio:.1f}%{Colors.RESET}")
        print(f"  {Colors.BLUE}🗑️ Cache Evictions: {stats['evictions']}{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Operations/Sec: {ops_per_second:.1f}{Colors.RESET}")
        print(f"  {Colors.CYAN}⏱️ Total Time: {total_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.WHITE}💾 Final Cache Size: {len(cache)}/{cache_size}{Colors.RESET}")

    def file_io_test(self, target):
        print(f"{Colors.CYAN}💾 Starting File I/O Performance Test{Colors.RESET}")
        
        file_size_mb = int(input(f"{Colors.YELLOW}Test file size in MB (default 10): {Colors.RESET}") or 10)
        operations = int(input(f"{Colors.YELLOW}Number of I/O operations (default 100): {Colors.RESET}") or 100)
        
        test_file = "io_test_file.bin"
        stats = {
            'write_times': [],
            'read_times': [],
            'write_speeds': [],
            'read_speeds': []
        }
        
        print(f"{Colors.MAGENTA}🎯 Testing file I/O with {file_size_mb}MB file and {operations} operations...{Colors.RESET}")
        
        # Generate test data
        test_data = os.urandom(1024 * 1024)  # 1MB of random data
        
        start_time = time.time()
        
        for i in range(operations):
            # Write test
            write_start = time.time()
            with open(test_file, 'wb') as f:
                for _ in range(file_size_mb):
                    f.write(test_data)
            write_time = time.time() - write_start
            write_speed = file_size_mb / write_time  # MB/s
            
            stats['write_times'].append(write_time)
            stats['write_speeds'].append(write_speed)
            
            # Read test
            read_start = time.time()
            with open(test_file, 'rb') as f:
                data = f.read()
            read_time = time.time() - read_start
            read_speed = file_size_mb / read_time  # MB/s
            
            stats['read_times'].append(read_time)
            stats['read_speeds'].append(read_speed)
            
            # Progress display
            progress = (i + 1) / operations * 100
            avg_write_speed = sum(stats['write_speeds']) / len(stats['write_speeds'])
            avg_read_speed = sum(stats['read_speeds']) / len(stats['read_speeds'])
            
            print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                  f"{Colors.GREEN}📝 Write: {avg_write_speed:.1f} MB/s | "
                  f"{Colors.BLUE}📖 Read: {avg_read_speed:.1f} MB/s{Colors.RESET}", end='')
        
        total_time = time.time() - start_time
        
        # Cleanup
        try:
            os.remove(test_file)
        except:
            pass
        
        # Calculate statistics
        avg_write_time = sum(stats['write_times']) / len(stats['write_times'])
        avg_read_time = sum(stats['read_times']) / len(stats['read_times'])
        avg_write_speed = sum(stats['write_speeds']) / len(stats['write_speeds'])
        avg_read_speed = sum(stats['read_speeds']) / len(stats['read_speeds'])
        max_write_speed = max(stats['write_speeds'])
        max_read_speed = max(stats['read_speeds'])
        
        print(f"\n\n{Colors.GREEN}🎊 File I/O Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 I/O Performance:{Colors.RESET}")
        print(f"  {Colors.GREEN}📝 Average Write Speed: {avg_write_speed:.1f} MB/s{Colors.RESET}")
        print(f"  {Colors.BLUE}📖 Average Read Speed: {avg_read_speed:.1f} MB/s{Colors.RESET}")
        print(f"  {Colors.YELLOW}📈 Peak Write Speed: {max_write_speed:.1f} MB/s{Colors.RESET}")
        print(f"  {Colors.MAGENTA}📊 Peak Read Speed: {max_read_speed:.1f} MB/s{Colors.RESET}")
        print(f"  {Colors.CYAN}⏱️ Average Write Time: {avg_write_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.WHITE}⏱️ Average Read Time: {avg_read_time:.2f}s{Colors.RESET}")
        print(f"  {Colors.BLUE}📦 Total Data Written: {file_size_mb * operations} MB{Colors.RESET}")
        print(f"  {Colors.GREEN}📦 Total Data Read: {file_size_mb * operations} MB{Colors.RESET}")

    def memory_leak_test(self, target):
        print(f"{Colors.CYAN}🧠 Starting Memory Leak Detection Test{Colors.RESET}")
        
        duration = int(input(f"{Colors.YELLOW}Test duration seconds (default 30): {Colors.RESET}") or 30)
        
        print(f"{Colors.MAGENTA}🎯 Monitoring memory usage for {duration} seconds...{Colors.RESET}")
        
        memory_samples = []
        start_memory = psutil.virtual_memory().used
        
        start_time = time.time()
        
        try:
            # Simulate memory allocation patterns
            allocated_objects = []
            
            for i in range(duration):
                # Allocate some memory
                data = [f"test_string_{j}" * 100 for j in range(1000)]
                allocated_objects.append(data)
                
                # Sample memory usage
                memory_info = psutil.virtual_memory()
                memory_samples.append({
                    'time': time.time() - start_time,
                    'used': memory_info.used,
                    'percent': memory_info.percent
                })
                
                # Occasionally release some memory (simulate garbage collection)
                if i % 5 == 0 and len(allocated_objects) > 10:
                    allocated_objects = allocated_objects[:-5]  # Remove last 5 items
                
                # Real-time display
                current_memory = memory_info.used / (1024 * 1024)  # Convert to MB
                memory_change = (current_memory - (start_memory / (1024 * 1024)))
                
                print(f"\r{Colors.CYAN}⏱️ Time: {i+1}/{duration}s | "
                      f"{Colors.GREEN}🧠 Memory: {current_memory:.1f} MB | "
                      f"{Colors.RED}📈 Change: {memory_change:+.1f} MB | "
                      f"{Colors.YELLOW}📊 Usage: {memory_info.percent:.1f}%{Colors.RESET}", end='')
                
                time.sleep(1)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Test interrupted{Colors.RESET}")
        
        total_time = time.time() - start_time
        
        # Analyze memory patterns
        if len(memory_samples) > 1:
            start_usage = memory_samples[0]['used']
            end_usage = memory_samples[-1]['used']
            memory_increase = end_usage - start_usage
            memory_increase_mb = memory_increase / (1024 * 1024)
            
            # Calculate memory growth rate
            usage_values = [s['used'] for s in memory_samples]
            avg_growth = (usage_values[-1] - usage_values[0]) / len(usage_values) if usage_values else 0
            
            print(f"\n\n{Colors.GREEN}🎊 Memory Leak Test Completed!{Colors.RESET}")
            print(f"{Colors.CYAN}📊 Memory Analysis:{Colors.RESET}")
            print(f"  {Colors.GREEN}🧠 Initial Memory: {start_usage / (1024 * 1024):.1f} MB{Colors.RESET}")
            print(f"  {Colors.BLUE}🧠 Final Memory: {end_usage / (1024 * 1024):.1f} MB{Colors.RESET}")
            print(f"  {Colors.RED}📈 Memory Increase: {memory_increase_mb:+.1f} MB{Colors.RESET}")
            print(f"  {Colors.YELLOW}📊 Average Growth: {avg_growth / 1024:.2f} KB/s{Colors.RESET}")
            
            if memory_increase_mb > 10:
                print(f"  {Colors.RED}⚠️  Potential memory leak detected!{Colors.RESET}")
            elif memory_increase_mb > 1:
                print(f"  {Colors.YELLOW}⚠️  Moderate memory growth observed{Colors.RESET}")
            else:
                print(f"  {Colors.GREEN}✅ Memory usage appears stable{Colors.RESET}")
            
            print(f"  {Colors.CYAN}⏱️ Test Duration: {total_time:.1f}s{Colors.RESET}")

    def load_balancer_test(self, target):
        print(f"{Colors.CYAN}⚖️ Starting Load Balancer Test for {target}{Colors.RESET}")
        
        requests_count = int(input(f"{Colors.YELLOW}Number of requests (default 100): {Colors.RESET}") or 100)
        concurrent_workers = int(input(f"{Colors.YELLOW}Concurrent workers (default 10): {Colors.RESET}") or 10)
        
        # Track which server responds (by Server header or IP)
        servers = {}
        response_times = []
        status_codes = {}
        
        def make_request(worker_id):
            for i in range(requests_count // concurrent_workers):
                try:
                    start_time = time.time()
                    response = requests.get(f"http://{target}", timeout=10)
                    response_time = (time.time() - start_time) * 1000
                    
                    # Identify server
                    server_id = response.headers.get('Server', 'Unknown')
                    if not server_id or server_id == 'Unknown':
                        server_id = response.headers.get('X-Server', 'Unknown')
                    
                    with lock:
                        response_times.append(response_time)
                        servers[server_id] = servers.get(server_id, 0) + 1
                        status_codes[response.status_code] = status_codes.get(response.status_code, 0) + 1
                    
                except Exception as e:
                    with lock:
                        servers['Error'] = servers.get('Error', 0) + 1
        
        print(f"{Colors.MAGENTA}🎯 Testing load balancer with {requests_count} requests...{Colors.RESET}")
        
        lock = threading.Lock()
        start_time = time.time()
        
        # Start worker threads
        threads = []
        for i in range(concurrent_workers):
            t = threading.Thread(target=make_request, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Monitor progress
        completed = 0
        while completed < requests_count and any(t.is_alive() for t in threads):
            time.sleep(0.5)
            with lock:
                completed = sum(servers.values())
            progress = (completed / requests_count) * 100
            
            print(f"\r{Colors.CYAN}📊 Progress: {progress:.1f}% | "
                  f"{Colors.GREEN}✅ Completed: {completed}/{requests_count}{Colors.RESET}", end='')
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        total_requests = sum(servers.values())
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        requests_per_second = total_requests / total_time if total_time > 0 else 0
        
        print(f"\n\n{Colors.GREEN}🎊 Load Balancer Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Load Distribution:{Colors.RESET}")
        
        for server, count in servers.items():
            percentage = (count / total_requests) * 100
            if server == 'Error':
                color = Colors.RED
            else:
                color = Colors.GREEN
            print(f"  {color}🖥️  {server}: {count} requests ({percentage:.1f}%){Colors.RESET}")
        
        print(f"\n{Colors.CYAN}📈 Performance Metrics:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Total Requests: {total_requests}{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️ Average Response Time: {avg_response_time:.2f}ms{Colors.RESET}")
        print(f"  {Colors.YELLOW}🚀 Requests/Sec: {requests_per_second:.1f}{Colors.RESET}")
        print(f"  {Colors.MAGENTA}📊 Test Duration: {total_time:.2f}s{Colors.RESET}")
        
        if status_codes:
            print(f"\n{Colors.CYAN}📋 Status Codes:{Colors.RESET}")
            for code, count in sorted(status_codes.items()):
                percentage = (count / total_requests) * 100
                color = Colors.GREEN if 200 <= code < 300 else Colors.YELLOW if 300 <= code < 400 else Colors.RED
                print(f"  {color}{code}: {count} ({percentage:.1f}%){Colors.RESET}")

    def session_stress_test(self, target):
        print(f"{Colors.CYAN}🔐 Starting Session Stress Test{Colors.RESET}")
        
        users = int(input(f"{Colors.YELLOW}Number of concurrent sessions (default 50): {Colors.RESET}") or 50)
        actions_per_user = int(input(f"{Colors.YELLOW}Actions per user (default 10): {Colors.RESET}") or 10)
        
        stats = {
            'sessions_created': 0,
            'sessions_failed': 0,
            'actions_completed': 0,
            'actions_failed': 0,
            'response_times': []
        }
        
        def user_session(user_id):
            session = requests.Session()
            
            try:
                # Simulate login
                login_data = {
                    'username': f'test_user_{user_id}',
                    'password': 'test_password'
                }
                
                # Try to login (this will likely fail, but we're testing session handling)
                response = session.post(f"http://{target}/login", data=login_data, timeout=5)
                
                with lock:
                    if response.status_code == 200:
                        stats['sessions_created'] += 1
                    else:
                        stats['sessions_failed'] += 1
                
                # Perform actions with session
                for action in range(actions_per_user):
                    try:
                        start_time = time.time()
                        
                        # Simulate different actions
                        actions = [
                            f"http://{target}/profile",
                            f"http://{target}/dashboard", 
                            f"http://{target}/settings",
                            f"http://{target}/api/user"
                        ]
                        
                        action_url = random.choice(actions)
                        response = session.get(action_url, timeout=5)
                        response_time = (time.time() - start_time) * 1000
                        
                        with lock:
                            stats['actions_completed'] += 1
                            stats['response_times'].append(response_time)
                        
                    except Exception as e:
                        with lock:
                            stats['actions_failed'] += 1
                
            except Exception as e:
                with lock:
                    stats['sessions_failed'] += 1
        
        print(f"{Colors.MAGENTA}🎯 Testing {users} concurrent sessions with {actions_per_user} actions each...{Colors.RESET}")
        
        lock = threading.Lock()
        start_time = time.time()
        
        # Start user sessions
        threads = []
        for i in range(users):
            t = threading.Thread(target=user_session, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Monitor progress
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(0.5)
                
                total_sessions = stats['sessions_created'] + stats['sessions_failed']
                total_actions = stats['actions_completed'] + stats['actions_failed']
                session_success = (stats['sessions_created'] / total_sessions * 100) if total_sessions > 0 else 0
                action_success = (stats['actions_completed'] / total_actions * 100) if total_actions > 0 else 0
                
                print(f"\r{Colors.CYAN}📊 Sessions: {stats['sessions_created']}/{users} | "
                      f"{Colors.GREEN}✅ Session Success: {session_success:.1f}% | "
                      f"{Colors.BLUE}🔧 Actions: {stats['actions_completed']} | "
                      f"{Colors.YELLOW}📈 Action Success: {action_success:.1f}%{Colors.RESET}", end='')
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}🛑 Test interrupted{Colors.RESET}")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        total_actions = stats['actions_completed'] + stats['actions_failed']
        avg_response_time = sum(stats['response_times']) / len(stats['response_times']) if stats['response_times'] else 0
        actions_per_second = stats['actions_completed'] / total_time if total_time > 0 else 0
        
        print(f"\n\n{Colors.GREEN}🎊 Session Stress Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Session Performance:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Sessions Created: {stats['sessions_created']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Sessions Failed: {stats['sessions_failed']}{Colors.RESET}")
        print(f"  {Colors.BLUE}🔧 Actions Completed: {stats['actions_completed']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}❌ Actions Failed: {stats['actions_failed']}{Colors.RESET}")
        print(f"  {Colors.MAGENTA}⏱️ Average Response Time: {avg_response_time:.2f}ms{Colors.RESET}")
        print(f"  {Colors.CYAN}🚀 Actions/Sec: {actions_per_second:.1f}{Colors.RESET}")
        print(f"  {Colors.WHITE}📊 Test Duration: {total_time:.2f}s{Colors.RESET}")