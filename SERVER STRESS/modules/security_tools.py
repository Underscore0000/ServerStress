import requests
import socket
import ssl
import json
import threading
import time
import random
import string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from utils.helpers import *
from utils.graphics import *

class SecurityTools:
    def __init__(self, graphics):
        self.graphics = graphics
        self.vulnerability_db = self._load_vulnerability_db()

    def _load_vulnerability_db(self):
        """Carica un database di vulnerabilità comuni"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3--",
                "'; DROP TABLE users--",
                "' OR 1=1--",
                "admin'--"
            ],
            'xss_payloads': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>"
            ],
            'common_paths': [
                "/admin", "/phpmyadmin", "/.git", "/backup", "/.env",
                "/wp-admin", "/server-status", "/config.php", "/.htaccess",
                "/backup.zip", "/database.sql", "/.DS_Store", "/web.config"
            ],
            'common_ports': [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
        }

    def vuln_scanner(self, target):
        print(f"{Colors.CYAN}🔍 Starting Comprehensive Vulnerability Scan for {target}{Colors.RESET}")
        
        scan_type = input(f"{Colors.YELLOW}Scan type (quick/full, default quick): {Colors.RESET}") or "quick"
        
        vulnerabilities_found = []
        stats = {'checks_performed': 0, 'vulnerabilities_found': 0}
        
        print(f"{Colors.MAGENTA}🎯 Scanning {target} for vulnerabilities...{Colors.RESET}")
        
        # 1. Directory and File Discovery
        print(f"\n{Colors.BLUE}📁 Scanning for exposed directories and files...{Colors.RESET}")
        for path in self.vulnerability_db['common_paths']:
            stats['checks_performed'] += 1
            url = f"http://{target}{path}"
            try:
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    vulnerabilities_found.append({
                        'type': 'Exposed Path',
                        'severity': 'Medium',
                        'description': f'Exposed path found: {path}',
                        'url': url,
                        'status_code': response.status_code
                    })
                    stats['vulnerabilities_found'] += 1
                    print(f"  {Colors.RED}❌ Found: {path} (Status: {response.status_code}){Colors.RESET}")
                else:
                    print(f"  {Colors.GREEN}✅ Not found: {path}{Colors.RESET}")
            except:
                print(f"  {Colors.YELLOW}⚠️  Error checking: {path}{Colors.RESET}")
        
        # 2. HTTP Security Headers Check
        print(f"\n{Colors.BLUE}🛡️ Checking HTTP Security Headers...{Colors.RESET}")
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options - Clickjacking vulnerability',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options - MIME sniffing vulnerability',
            'X-XSS-Protection': 'Missing X-XSS-Protection - XSS protection not enabled',
            'Strict-Transport-Security': 'Missing HSTS - SSL stripping vulnerability',
            'Content-Security-Policy': 'Missing Content-Security-Policy - XSS protection weakened'
        }
        
        try:
            response = requests.get(f"http://{target}", timeout=10, verify=False)
            stats['checks_performed'] += len(security_headers)
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    vulnerabilities_found.append({
                        'type': 'Missing Security Header',
                        'severity': 'Low',
                        'description': description,
                        'url': f"http://{target}",
                        'details': f'Header {header} is missing'
                    })
                    stats['vulnerabilities_found'] += 1
                    print(f"  {Colors.RED}❌ Missing: {header}{Colors.RESET}")
                else:
                    print(f"  {Colors.GREEN}✅ Present: {header}{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠️  Error checking headers: {e}{Colors.RESET}")
        
        # 3. SSL/TLS Configuration Check
        print(f"\n{Colors.BLUE}🔐 Checking SSL/TLS Configuration...{Colors.RESET}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Check for weak protocols
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1']:
                        vulnerabilities_found.append({
                            'type': 'Weak SSL/TLS Protocol',
                            'severity': 'High',
                            'description': f'Using weak protocol: {protocol}',
                            'details': 'Consider disabling weak protocols'
                        })
                        stats['vulnerabilities_found'] += 1
                        print(f"  {Colors.RED}❌ Weak protocol: {protocol}{Colors.RESET}")
                    else:
                        print(f"  {Colors.GREEN}✅ Secure protocol: {protocol}{Colors.RESET}")
                    
                    # Check certificate expiration
                    from datetime import datetime
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        vulnerabilities_found.append({
                            'type': 'SSL Certificate Expiring Soon',
                            'severity': 'Medium',
                            'description': f'SSL certificate expires in {days_until_expiry} days',
                            'details': 'Renew SSL certificate soon'
                        })
                        stats['vulnerabilities_found'] += 1
                        print(f"  {Colors.RED}❌ Certificate expires in {days_until_expiry} days{Colors.RESET}")
                    else:
                        print(f"  {Colors.GREEN}✅ Certificate valid for {days_until_expiry} days{Colors.RESET}")
                        
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠️  SSL check failed: {e}{Colors.RESET}")
        
        # 4. Server Information Disclosure
        print(f"\n{Colors.BLUE}🖥️ Checking for Server Information Disclosure...{Colors.RESET}")
        try:
            response = requests.get(f"http://{target}", timeout=10, verify=False)
            server_header = response.headers.get('Server', '')
            x_powered_by = response.headers.get('X-Powered-By', '')
            
            if server_header:
                vulnerabilities_found.append({
                    'type': 'Server Information Disclosure',
                    'severity': 'Low',
                    'description': f'Server header reveals: {server_header}',
                    'details': 'Consider removing or obfuscating server information'
                })
                stats['vulnerabilities_found'] += 1
                print(f"  {Colors.RED}❌ Server header: {server_header}{Colors.RESET}")
            
            if x_powered_by:
                vulnerabilities_found.append({
                    'type': 'Technology Information Disclosure',
                    'severity': 'Low',
                    'description': f'X-Powered-By reveals: {x_powered_by}',
                    'details': 'Consider removing technology information'
                })
                stats['vulnerabilities_found'] += 1
                print(f"  {Colors.RED}❌ X-Powered-By: {x_powered_by}{Colors.RESET}")
                
            if not server_header and not x_powered_by:
                print(f"  {Colors.GREEN}✅ No server information disclosed{Colors.RESET}")
                
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠️  Error checking server info: {e}{Colors.RESET}")
        
        # Display Results
        print(f"\n{Colors.GREEN}🎊 Vulnerability Scan Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Scan Summary:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Checks performed: {stats['checks_performed']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Vulnerabilities found: {stats['vulnerabilities_found']}{Colors.RESET}")
        
        if vulnerabilities_found:
            print(f"\n{Colors.RED}🚨 VULNERABILITIES FOUND:{Colors.RESET}")
            for vuln in vulnerabilities_found:
                color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW if vuln['severity'] == 'Medium' else Colors.BLUE
                print(f"\n{color}🔍 {vuln['type']} ({vuln['severity']}){Colors.RESET}")
                print(f"  {Colors.WHITE}Description: {vuln['description']}{Colors.RESET}")
                if 'url' in vuln:
                    print(f"  {Colors.WHITE}URL: {vuln['url']}{Colors.RESET}")
                if 'details' in vuln:
                    print(f"  {Colors.WHITE}Details: {vuln['details']}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✅ No critical vulnerabilities found!{Colors.RESET}")

    def ssl_analyzer(self, target):
        print(f"{Colors.CYAN}🔐 Starting Comprehensive SSL/TLS Analysis for {target}{Colors.RESET}")
        
        try:
            print(f"{Colors.MAGENTA}🎯 Analyzing SSL/TLS configuration...{Colors.RESET}")
            
            # Test multiple SSL/TLS versions
            ssl_versions = {
                'SSLv2': ssl.PROTOCOL_SSLv2,
                'SSLv3': ssl.PROTOCOL_SSLv3,
                'TLSv1': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
                'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None
            }
            
            supported_versions = []
            weak_versions = []
            
            for version_name, version_protocol in ssl_versions.items():
                if version_protocol is None:
                    continue
                    
                try:
                    context = ssl.SSLContext(version_protocol)
                    context.verify_mode = ssl.CERT_NONE
                    context.check_hostname = False
                    
                    with socket.create_connection((target, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            supported_versions.append(version_name)
                            
                            if version_name in ['SSLv2', 'SSLv3', 'TLSv1']:
                                weak_versions.append(version_name)
                                
                            print(f"  {Colors.GREEN}✅ {version_name}: Supported{Colors.RESET}")
                            
                except Exception as e:
                    print(f"  {Colors.RED}❌ {version_name}: Not supported{Colors.RESET}")
            
            # Get detailed certificate information
            print(f"\n{Colors.BLUE}📜 Certificate Analysis...{Colors.RESET}")
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Certificate details
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    # Certificate expiration
                    from datetime import datetime
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    print(f"  {Colors.GREEN}📝 Subject: {subject}{Colors.RESET}")
                    print(f"  {Colors.BLUE}🏢 Issuer: {issuer}{Colors.RESET}")
                    print(f"  {Colors.YELLOW}📅 Valid from: {cert['notBefore']}{Colors.RESET}")
                    print(f"  {Colors.MAGENTA}📅 Valid until: {cert['notAfter']}{Colors.RESET}")
                    print(f"  {Colors.CYAN}⏱️ Days until expiry: {days_until_expiry}{Colors.RESET}")
                    
                    # Cipher information
                    print(f"\n{Colors.BLUE}🔒 Cipher Information:{Colors.RESET}")
                    print(f"  {Colors.GREEN}Protocol: {protocol}{Colors.RESET}")
                    print(f"  {Colors.BLUE}Cipher: {cipher[0]}{Colors.RESET}")
                    print(f"  {Colors.YELLOW}Bits: {cipher[1]}{Colors.RESET}")
                    print(f"  {Colors.MAGENTA}Version: {cipher[2]}{Colors.RESET}")
            
            # Security Assessment
            print(f"\n{Colors.CYAN}📊 Security Assessment:{Colors.RESET}")
            
            if weak_versions:
                print(f"  {Colors.RED}❌ WEAK PROTOCOLS: {', '.join(weak_versions)}{Colors.RESET}")
                print(f"  {Colors.YELLOW}⚠️  Recommendation: Disable weak SSL/TLS versions{Colors.RESET}")
            else:
                print(f"  {Colors.GREEN}✅ No weak protocols detected{Colors.RESET}")
            
            if days_until_expiry < 30:
                print(f"  {Colors.RED}❌ CERTIFICATE EXPIRING: {days_until_expiry} days{Colors.RESET}")
                print(f"  {Colors.YELLOW}⚠️  Recommendation: Renew SSL certificate{Colors.RESET}")
            else:
                print(f"  {Colors.GREEN}✅ Certificate validity: OK{Colors.RESET}")
            
            if cipher[1] < 128:
                print(f"  {Colors.RED}❌ WEAK CIPHER: {cipher[1]} bits{Colors.RESET}")
                print(f"  {Colors.YELLOW}⚠️  Recommendation: Use stronger cipher (>= 128 bits){Colors.RESET}")
            else:
                print(f"  {Colors.GREEN}✅ Cipher strength: OK{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}❌ SSL analysis failed: {e}{Colors.RESET}")

    def cors_tester(self, target):
        print(f"{Colors.CYAN}🌐 Starting CORS (Cross-Origin Resource Sharing) Test for {target}{Colors.RESET}")
        
        # Test various CORS configurations
        origins_to_test = [
            'https://evil.com',
            'http://attacker.com',
            'https://trusted.com',
            'null',
            target.replace('https://', 'https://evil.'),
            target.replace('http://', 'http://attacker.')
        ]
        
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        headers_to_test = ['X-Custom-Header', 'Authorization', 'Content-Type']
        
        vulnerable_configs = []
        
        print(f"{Colors.MAGENTA}🎯 Testing CORS configurations...{Colors.RESET}")
        
        for origin in origins_to_test:
            try:
                # Test OPTIONS preflight request
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'X-Custom-Header'
                }
                
                response = requests.options(f"https://{target}", headers=headers, timeout=10, verify=False)
                
                # Check for permissive CORS headers
                cors_headers = {
                    'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                    'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                    'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                    'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers')
                }
                
                # Analyze CORS configuration
                if cors_headers['Access-Control-Allow-Origin'] == '*' or cors_headers['Access-Control-Allow-Origin'] == origin:
                    if cors_headers['Access-Control-Allow-Credentials'] == 'true':
                        # Highly vulnerable - credentials with wildcard origin
                        vulnerable_configs.append({
                            'origin': origin,
                            'severity': 'Critical',
                            'issue': 'Credentials allowed with wildcard origin',
                            'headers': cors_headers
                        })
                        print(f"  {Colors.RED}❌ CRITICAL: {origin} - Credentials with wildcard{Colors.RESET}")
                    else:
                        # Medium vulnerability - wildcard origin without credentials
                        vulnerable_configs.append({
                            'origin': origin,
                            'severity': 'Medium',
                            'issue': 'Wildcard origin allowed',
                            'headers': cors_headers
                        })
                        print(f"  {Colors.YELLOW}⚠️  MEDIUM: {origin} - Wildcard origin{Colors.RESET}")
                elif cors_headers['Access-Control-Allow-Origin'] and cors_headers['Access-Control-Allow-Origin'] != origin:
                    # Reflected origin - potential vulnerability
                    vulnerable_configs.append({
                        'origin': origin,
                        'severity': 'Low',
                        'issue': 'Origin reflection detected',
                        'headers': cors_headers
                    })
                    print(f"  {Colors.BLUE}🔍 LOW: {origin} - Origin reflection{Colors.RESET}")
                else:
                    print(f"  {Colors.GREEN}✅ SECURE: {origin} - Properly restricted{Colors.RESET}")
                    
            except Exception as e:
                print(f"  {Colors.YELLOW}⚠️  ERROR: {origin} - {e}{Colors.RESET}")
        
        # Display Results
        print(f"\n{Colors.GREEN}🎊 CORS Testing Completed!{Colors.RESET}")
        
        if vulnerable_configs:
            print(f"\n{Colors.RED}🚨 CORS VULNERABILITIES DETECTED:{Colors.RESET}")
            for config in vulnerable_configs:
                color = Colors.RED if config['severity'] == 'Critical' else Colors.YELLOW if config['severity'] == 'Medium' else Colors.BLUE
                print(f"\n{color}🔍 {config['severity']} - {config['issue']}{Colors.RESET}")
                print(f"  {Colors.WHITE}Origin: {config['origin']}{Colors.RESET}")
                for header, value in config['headers'].items():
                    if value:
                        print(f"  {Colors.WHITE}{header}: {value}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✅ No CORS vulnerabilities detected!{Colors.RESET}")

    def http_header_analyzer(self, target):
        print(f"{Colors.CYAN}📋 Starting HTTP Header Analysis for {target}{Colors.RESET}")
        
        protocols = ['http', 'https']
        all_headers = {}
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{target}"
                print(f"\n{Colors.MAGENTA}🎯 Analyzing {url}...{Colors.RESET}")
                
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                all_headers[protocol] = dict(response.headers)
                
                # Security Headers Check
                security_headers = {
                    'Strict-Transport-Security': 'HSTS - Forces HTTPS',
                    'Content-Security-Policy': 'CSP - XSS Protection',
                    'X-Frame-Options': 'Clickjacking Protection',
                    'X-Content-Type-Options': 'MIME Sniffing Protection',
                    'X-XSS-Protection': 'XSS Protection',
                    'Referrer-Policy': 'Referrer Information Control',
                    'Feature-Policy': 'Browser Features Control',
                    'Permissions-Policy': 'Permissions Control'
                }
                
                print(f"{Colors.BLUE}🛡️ Security Headers:{Colors.RESET}")
                for header, description in security_headers.items():
                    if header in response.headers:
                        print(f"  {Colors.GREEN}✅ {header}: {response.headers[header]} - {description}{Colors.RESET}")
                    else:
                        print(f"  {Colors.RED}❌ {header}: MISSING - {description}{Colors.RESET}")
                
                # Information Disclosure Headers
                info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
                print(f"\n{Colors.BLUE}🖥️ Information Headers:{Colors.RESET}")
                for header in info_headers:
                    if header in response.headers:
                        print(f"  {Colors.YELLOW}⚠️  {header}: {response.headers[header]} - Information disclosure{Colors.RESET}")
                    else:
                        print(f"  {Colors.GREEN}✅ {header}: Not present{Colors.RESET}")
                
                # Cache and Performance Headers
                cache_headers = ['Cache-Control', 'ETag', 'Last-Modified', 'Expires']
                print(f"\n{Colors.BLUE}⚡ Cache Headers:{Colors.RESET}")
                for header in cache_headers:
                    if header in response.headers:
                        print(f"  {Colors.BLUE}📦 {header}: {response.headers[header]}{Colors.RESET}")
                    else:
                        print(f"  {Colors.YELLOW}⚠️  {header}: Not present{Colors.RESET}")
                        
            except Exception as e:
                print(f"  {Colors.RED}❌ Error analyzing {protocol}: {e}{Colors.RESET}")
        
        # Generate Security Score
        print(f"\n{Colors.CYAN}📊 Security Header Score:{Colors.RESET}")
        
        for protocol, headers in all_headers.items():
            score = 0
            max_score = 8  # Based on 8 key security headers
            
            security_headers_list = [
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy'
            ]
            
            for header in security_headers_list:
                if header in headers:
                    score += 1
            
            security_percentage = (score / max_score) * 100
            
            if security_percentage >= 80:
                color = Colors.GREEN
                rating = "EXCELLENT"
            elif security_percentage >= 60:
                color = Colors.YELLOW
                rating = "GOOD"
            elif security_percentage >= 40:
                color = Colors.ORANGE
                rating = "FAIR"
            else:
                color = Colors.RED
                rating = "POOR"
            
            print(f"  {color}{protocol.upper()}: {score}/{max_score} ({security_percentage:.1f}%) - {rating}{Colors.RESET}")

    def brute_force_tester(self, target):
        print(f"{Colors.CYAN}🔑 Starting Brute Force Resistance Test for {target}{Colors.RESET}")
        
        # This is a SIMULATION - we don't actually brute force real services
        # We test response times and behavior patterns
        
        test_type = input(f"{Colors.YELLOW}Test type (login/directory/api, default login): {Colors.RESET}") or "login"
        attempts = int(input(f"{Colors.YELLOW}Number of test attempts (default 50): {Colors.RESET}") or 50)
        
        print(f"{Colors.MAGENTA}🎯 Testing brute force resistance with {attempts} attempts...{Colors.RESET}")
        
        response_times = []
        status_codes = {}
        lockout_detected = False
        captcha_detected = False
        
        # Common username/password combinations for testing
        test_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('test', 'test'),
            ('user', 'user')
        ]
        
        for i in range(attempts):
            try:
                # Rotate through test credentials
                username, password = test_credentials[i % len(test_credentials)]
                
                start_time = time.time()
                
                if test_type == 'login':
                    # Simulate login attempt
                    login_data = {
                        'username': username,
                        'password': password,
                        'csrf_token': 'test'  # Simulate CSRF token
                    }
                    response = requests.post(f"http://{target}/login", data=login_data, timeout=5, allow_redirects=False)
                
                elif test_type == 'directory':
                    # Test directory access
                    test_dir = f"/{''.join(random.choices(string.ascii_lowercase, k=8))}"
                    response = requests.get(f"http://{target}{test_dir}", timeout=5)
                
                elif test_type == 'api':
                    # Test API endpoint
                    response = requests.get(f"http://{target}/api/test", timeout=5)
                
                response_time = (time.time() - start_time) * 1000
                response_times.append(response_time)
                
                # Track status codes
                status_code = response.status_code
                status_codes[status_code] = status_codes.get(status_code, 0) + 1
                
                # Check for security mechanisms
                if response.status_code == 429:  # Too Many Requests
                    lockout_detected = True
                    print(f"  {Colors.GREEN}✅ Attempt {i+1}: Rate limiting detected (429){Colors.RESET}")
                elif 'captcha' in response.text.lower() or 'recaptcha' in response.text.lower():
                    captcha_detected = True
                    print(f"  {Colors.GREEN}✅ Attempt {i+1}: CAPTCHA detected{Colors.RESET}")
                elif response.status_code == 403:  # Forbidden
                    print(f"  {Colors.YELLOW}⚠️  Attempt {i+1}: Access forbidden (403){Colors.RESET}")
                elif response.status_code == 401:  # Unauthorized
                    print(f"  {Colors.RED}❌ Attempt {i+1}: Authentication failed (401){Colors.RESET}")
                else:
                    print(f"  {Colors.BLUE}🔍 Attempt {i+1}: Status {response.status_code} - {response_time:.1f}ms{Colors.RESET}")
                
                # Add delay to avoid being too aggressive
                time.sleep(0.5)
                
            except Exception as e:
                print(f"  {Colors.YELLOW}⚠️  Attempt {i+1}: Error - {e}{Colors.RESET}")
                response_times.append(0)
        
        # Analyze results
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        
        print(f"\n{Colors.GREEN}🎊 Brute Force Test Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Security Analysis:{Colors.RESET}")
        
        if lockout_detected:
            print(f"  {Colors.GREEN}✅ Rate limiting: DETECTED{Colors.RESET}")
        else:
            print(f"  {Colors.RED}❌ Rate limiting: NOT DETECTED{Colors.RESET}")
        
        if captcha_detected:
            print(f"  {Colors.GREEN}✅ CAPTCHA protection: DETECTED{Colors.RESET}")
        else:
            print(f"  {Colors.RED}❌ CAPTCHA protection: NOT DETECTED{Colors.RESET}")
        
        print(f"  {Colors.BLUE}⏱️ Average response time: {avg_response_time:.1f}ms{Colors.RESET}")
        print(f"  {Colors.YELLOW}📈 Maximum response time: {max_response_time:.1f}ms{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}📋 Response Distribution:{Colors.RESET}")
        for code, count in sorted(status_codes.items()):
            percentage = (count / attempts) * 100
            color = Colors.GREEN if code == 429 else Colors.RED if code == 200 else Colors.YELLOW
            print(f"  {color}{code}: {count} attempts ({percentage:.1f}%){Colors.RESET}")
        
        # Security Recommendations
        print(f"\n{Colors.CYAN}💡 Security Recommendations:{Colors.RESET}")
        if not lockout_detected:
            print(f"  {Colors.YELLOW}⚠️  Implement rate limiting{Colors.RESET}")
        if not captcha_detected:
            print(f"  {Colors.YELLOW}⚠️  Consider adding CAPTCHA after multiple failures{Colors.RESET}")
        if 200 in status_codes and test_type == 'login':
            print(f"  {Colors.YELLOW}⚠️  Some attempts returned 200 - check authentication logic{Colors.RESET}")

    def security_headers_check(self, target):
        print(f"{Colors.CYAN}🛡️ Starting Comprehensive Security Headers Check for {target}{Colors.RESET}")
        
        # Comprehensive security headers database
        security_headers_db = {
            'Strict-Transport-Security': {
                'description': 'Forces HTTPS connections',
                'recommended': 'max-age=31536000; includeSubDomains',
                'severity': 'High'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS attacks',
                'recommended': "default-src 'self'",
                'severity': 'High'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking',
                'recommended': 'DENY or SAMEORIGIN',
                'severity': 'High'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME sniffing',
                'recommended': 'nosniff',
                'severity': 'Medium'
            },
            'X-XSS-Protection': {
                'description': 'XSS protection for older browsers',
                'recommended': '1; mode=block',
                'severity': 'Medium'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'recommended': 'strict-origin-when-cross-origin',
                'severity': 'Medium'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features',
                'recommended': 'Controls features like camera, microphone',
                'severity': 'Medium'
            },
            'Feature-Policy': {
                'description': 'Controls browser features (older)',
                'recommended': 'Controls features like camera, microphone',
                'severity': 'Low'
            }
        }
        
        results = {}
        score = 0
        max_score = len(security_headers_db)
        
        try:
            response = requests.get(f"https://{target}", timeout=10, verify=False)
            if response.status_code != 200:
                response = requests.get(f"http://{target}", timeout=10, verify=False)
            
            print(f"{Colors.MAGENTA}🎯 Analyzing security headers...{Colors.RESET}")
            
            for header, info in security_headers_db.items():
                if header in response.headers:
                    score += 1
                    results[header] = {
                        'status': 'PRESENT',
                        'value': response.headers[header],
                        'description': info['description'],
                        'severity': info['severity']
                    }
                    color = Colors.GREEN
                    status_icon = "✅"
                else:
                    results[header] = {
                        'status': 'MISSING',
                        'value': None,
                        'description': info['description'],
                        'severity': info['severity']
                    }
                    color = Colors.RED
                    status_icon = "❌"
                
                print(f"  {color}{status_icon} {header}: {results[header]['status']}{Colors.RESET}")
            
            # Calculate security score
            security_percentage = (score / max_score) * 100
            
            print(f"\n{Colors.CYAN}📊 Security Headers Score: {score}/{max_score} ({security_percentage:.1f}%){Colors.RESET}")
            
            if security_percentage >= 90:
                print(f"  {Colors.GREEN}🎉 EXCELLENT - Strong security headers configuration{Colors.RESET}")
            elif security_percentage >= 70:
                print(f"  {Colors.YELLOW}👍 GOOD - Good security headers configuration{Colors.RESET}")
            elif security_percentage >= 50:
                print(f"  {Colors.ORANGE}⚠️  FAIR - Basic security headers present{Colors.RESET}")
            else:
                print(f"  {Colors.RED}🚨 POOR - Weak security headers configuration{Colors.RESET}")
            
            # Detailed report
            print(f"\n{Colors.CYAN}📋 Detailed Header Analysis:{Colors.RESET}")
            for header, result in results.items():
                severity_color = Colors.RED if result['severity'] == 'High' else Colors.YELLOW if result['severity'] == 'Medium' else Colors.BLUE
                status_color = Colors.GREEN if result['status'] == 'PRESENT' else Colors.RED
                
                print(f"\n{severity_color}🔍 {header} ({result['severity']}){Colors.RESET}")
                print(f"  {Colors.WHITE}Description: {result['description']}{Colors.RESET}")
                print(f"  {status_color}Status: {result['status']}{Colors.RESET}")
                if result['value']:
                    print(f"  {Colors.WHITE}Value: {result['value']}{Colors.RESET}")
                else:
                    print(f"  {Colors.RED}Recommendation: Implement {header} header{Colors.RESET}")
                    
        except Exception as e:
            print(f"{Colors.RED}❌ Security headers check failed: {e}{Colors.RESET}")

    def sql_injection_tester(self, target):
        print(f"{Colors.CYAN}💉 Starting SQL Injection Vulnerability Test for {target}{Colors.RESET}")
        
        # This is a BASIC simulation for educational purposes
        # Real SQL injection testing requires careful, authorized testing
        
        print(f"{Colors.YELLOW}⚠️  This is a simulated test for educational purposes only{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  Always get proper authorization before testing real systems{Colors.RESET}")
        
        test_endpoints = [
            f"http://{target}/search?q=test",
            f"http://{target}/products?id=1",
            f"http://{target}/user?name=admin",
            f"http://{target}/login"
        ]
        
        sql_payloads = self.vulnerability_db['sql_injection']
        vulnerabilities_found = []
        
        print(f"{Colors.MAGENTA}🎯 Testing for SQL injection vulnerabilities...{Colors.RESET}")
        
        for endpoint in test_endpoints:
            print(f"\n{Colors.BLUE}🔍 Testing endpoint: {endpoint}{Colors.RESET}")
            
            for payload in sql_payloads[:3]:  # Test first 3 payloads for simulation
                try:
                    # Test in URL parameters
                    test_url = endpoint + payload
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Analyze response for SQL injection indicators
                    indicators = [
                        'sql' in response.text.lower(),
                        'syntax' in response.text.lower(),
                        'mysql' in response.text.lower(),
                        'ora-' in response.text.lower(),
                        'error' in response.text.lower(),
                        'warning' in response.text.lower(),
                        'unclosed' in response.text.lower(),
                        response.status_code == 500
                    ]
                    
                    if any(indicators):
                        vulnerabilities_found.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'evidence': 'Error message in response',
                            'severity': 'High'
                        })
                        print(f"  {Colors.RED}❌ VULNERABLE: {payload}{Colors.RESET}")
                    else:
                        print(f"  {Colors.GREEN}✅ SECURE: {payload}{Colors.RESET}")
                    
                    time.sleep(0.5)  # Be polite
                    
                except Exception as e:
                    print(f"  {Colors.YELLOW}⚠️  ERROR: {payload} - {e}{Colors.RESET}")
        
        # Display Results
        print(f"\n{Colors.GREEN}🎊 SQL Injection Test Completed!{Colors.RESET}")
        
        if vulnerabilities_found:
            print(f"\n{Colors.RED}🚨 SQL INJECTION VULNERABILITIES DETECTED:{Colors.RESET}")
            for vuln in vulnerabilities_found:
                print(f"\n{Colors.RED}💉 {vuln['severity']} Vulnerability{Colors.RESET}")
                print(f"  {Colors.WHITE}Endpoint: {vuln['endpoint']}{Colors.RESET}")
                print(f"  {Colors.WHITE}Payload: {vuln['payload']}{Colors.RESET}")
                print(f"  {Colors.WHITE}Evidence: {vuln['evidence']}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✅ No SQL injection vulnerabilities detected in basic tests{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}💡 Security Recommendations:{Colors.RESET}")
        print(f"  {Colors.YELLOW}1. Use parameterized queries/prepared statements{Colors.RESET}")
        print(f"  {Colors.YELLOW}2. Implement input validation and sanitization{Colors.RESET}")
        print(f"  {Colors.YELLOW}3. Use ORM frameworks with built-in protection{Colors.RESET}")
        print(f"  {Colors.YELLOW}4. Implement proper error handling{Colors.RESET}")
        print(f"  {Colors.YELLOW}5. Regular security testing and code reviews{Colors.RESET}")

    def xss_tester(self, target):
        print(f"{Colors.CYAN}🦂 Starting XSS (Cross-Site Scripting) Vulnerability Test for {target}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}⚠️  This is a simulated test for educational purposes only{Colors.RESET}")
        
        xss_payloads = self.vulnerability_db['xss_payloads']
        test_endpoints = [
            f"http://{target}/search?q=test",
            f"http://{target}/contact?name=test",
            f"http://{target}/comment=test",
            f"http://{target}/profile?user=test"
        ]
        
        vulnerabilities_found = []
        
        print(f"{Colors.MAGENTA}🎯 Testing for XSS vulnerabilities...{Colors.RESET}")
        
        for endpoint in test_endpoints:
            print(f"\n{Colors.BLUE}🔍 Testing endpoint: {endpoint}{Colors.RESET}")
            
            for payload in xss_payloads[:3]:  # Test first 3 payloads
                try:
                    test_url = endpoint.replace('test', payload)
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        vulnerabilities_found.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'evidence': 'Payload reflected in response',
                            'severity': 'High'
                        })
                        print(f"  {Colors.RED}❌ VULNERABLE: XSS payload reflected{Colors.RESET}")
                    else:
                        print(f"  {Colors.GREEN}✅ SECURE: Payload not reflected{Colors.RESET}")
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"  {Colors.YELLOW}⚠️  ERROR: {e}{Colors.RESET}")
        
        # Display Results
        print(f"\n{Colors.GREEN}🎊 XSS Test Completed!{Colors.RESET}")
        
        if vulnerabilities_found:
            print(f"\n{Colors.RED}🚨 XSS VULNERABILITIES DETECTED:{Colors.RESET}")
            for vuln in vulnerabilities_found:
                print(f"\n{Colors.RED}🦂 {vuln['severity']} XSS Vulnerability{Colors.RESET}")
                print(f"  {Colors.WHITE}Endpoint: {vuln['endpoint']}{Colors.RESET}")
                print(f"  {Colors.WHITE}Payload: {vuln['payload']}{Colors.RESET}")
                print(f"  {Colors.WHITE}Evidence: {vuln['evidence']}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✅ No reflected XSS vulnerabilities detected in basic tests{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}💡 Security Recommendations:{Colors.RESET}")
        print(f"  {Colors.YELLOW}1. Implement Content Security Policy (CSP){Colors.RESET}")
        print(f"  {Colors.YELLOW}2. Use proper output encoding{Colors.RESET}")
        print(f"  {Colors.YELLOW}3. Validate and sanitize all user input{Colors.RESET}")
        print(f"  {Colors.YELLOW}4. Use HTTPOnly cookies for session management{Colors.RESET}")
        print(f"  {Colors.YELLOW}5. Regular security testing{Colors.RESET}")

    def csrf_tester(self, target):
        print(f"{Colors.CYAN}🎭 Starting CSRF (Cross-Site Request Forgery) Test for {target}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}⚠️  This test checks for basic CSRF protection mechanisms{Colors.RESET}")
        
        # Test endpoints that might be vulnerable to CSRF
        test_endpoints = [
            f"http://{target}/changepassword",
            f"http://{target}/updateprofile",
            f"http://{target}/transferfunds",
            f"http://{target}/deleteaccount"
        ]
        
        protection_mechanisms = {
            'CSRF_Token': False,
            'SameSite_Cookies': False,
            'Custom_Header': False,
            'Referer_Check': False
        }
        
        print(f"{Colors.MAGENTA}🎯 Checking CSRF protection mechanisms...{Colors.RESET}")
        
        try:
            # First, get the main page to check for CSRF tokens
            response = requests.get(f"http://{target}", timeout=10, verify=False)
            
            # Check for CSRF tokens in forms
            if 'csrf' in response.text.lower() or '_token' in response.text.lower():
                protection_mechanisms['CSRF_Token'] = True
                print(f"  {Colors.GREEN}✅ CSRF tokens detected in forms{Colors.RESET}")
            else:
                print(f"  {Colors.RED}❌ No CSRF tokens detected in forms{Colors.RESET}")
            
            # Check cookies for SameSite attribute
            cookies = response.cookies
            for cookie in cookies:
                if hasattr(cookie, 'same_site') and cookie.same_site:
                    protection_mechanisms['SameSite_Cookies'] = True
                    print(f"  {Colors.GREEN}✅ SameSite cookie attribute found: {cookie.name}{Colors.RESET}")
                    break
            else:
                print(f"  {Colors.RED}❌ No SameSite cookie attributes found{Colors.RESET}")
            
            # Check for custom headers in forms
            if 'x-csrf-token' in response.text.lower() or 'x-requested-with' in response.text.lower():
                protection_mechanisms['Custom_Header'] = True
                print(f"  {Colors.GREEN}✅ Custom anti-CSRF headers detected{Colors.RESET}")
            else:
                print(f"  {Colors.RED}❌ No custom anti-CSRF headers detected{Colors.RESET}")
            
            # Test if Referer header is checked (basic test)
            test_response = requests.post(f"http://{target}/", headers={'Referer': 'https://evil.com'}, timeout=5)
            if test_response.status_code == 403 or 'referer' in test_response.text.lower():
                protection_mechanisms['Referer_Check'] = True
                print(f"  {Colors.GREEN}✅ Referer header validation detected{Colors.RESET}")
            else:
                print(f"  {Colors.RED}❌ No Referer header validation detected{Colors.RESET}")
                
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠️  Error during CSRF testing: {e}{Colors.RESET}")
        
        # Calculate CSRF protection score
        protections_found = sum(protection_mechanisms.values())
        total_protections = len(protection_mechanisms)
        protection_score = (protections_found / total_protections) * 100
        
        print(f"\n{Colors.GREEN}🎊 CSRF Protection Analysis Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 CSRF Protection Score: {protections_found}/{total_protections} ({protection_score:.1f}%){Colors.RESET}")
        
        if protection_score >= 75:
            print(f"  {Colors.GREEN}🎉 EXCELLENT - Strong CSRF protection{Colors.RESET}")
        elif protection_score >= 50:
            print(f"  {Colors.YELLOW}👍 GOOD - Basic CSRF protection{Colors.RESET}")
        elif protection_score >= 25:
            print(f"  {Colors.ORANGE}⚠️  FAIR - Some CSRF protection{Colors.RESET}")
        else:
            print(f"  {Colors.RED}🚨 POOR - Weak CSRF protection{Colors.RESET}")
        
        # Recommendations
        print(f"\n{Colors.CYAN}💡 CSRF Protection Recommendations:{Colors.RESET}")
        if not protection_mechanisms['CSRF_Token']:
            print(f"  {Colors.YELLOW}⚠️  Implement CSRF tokens in all state-changing forms{Colors.RESET}")
        if not protection_mechanisms['SameSite_Cookies']:
            print(f"  {Colors.YELLOW}⚠️  Set SameSite attributes on session cookies{Colors.RESET}")
        if not protection_mechanisms['Custom_Header']:
            print(f"  {Colors.YELLOW}⚠️  Consider using custom headers for AJAX requests{Colors.RESET}")
        if not protection_mechanisms['Referer_Check']:
            print(f"  {Colors.YELLOW}⚠️  Implement Referer header validation{Colors.RESET}")

    def directory_bruteforce(self, target):
        print(f"{Colors.CYAN}📁 Starting Directory Bruteforce for {target}{Colors.RESET}")
        
        wordlist_size = input(f"{Colors.YELLOW}Wordlist size (small/medium/large, default small): {Colors.RESET}") or "small"
        
        # Different sized wordlists
        wordlists = {
            'small': [
                'admin', 'login', 'dashboard', 'config', 'backup', 'database',
                'upload', 'images', 'css', 'js', 'api', 'test', 'dev', 'tmp',
                'backup', 'archive', 'old', 'new', '2024', '2023'
            ],
            'medium': [
                'admin', 'administrator', 'login', 'logout', 'dashboard', 'panel',
                'config', 'configuration', 'backup', 'backups', 'database', 'sql',
                'upload', 'uploads', 'images', 'img', 'css', 'js', 'javascript',
                'api', 'rest', 'graphql', 'test', 'testing', 'dev', 'development',
                'tmp', 'temp', 'backup', 'backups', 'archive', 'archives',
                'old', 'new', '2024', '2023', '2022', 'secret', 'hidden'
            ],
            'large': [
                'admin', 'administrator', 'login', 'logout', 'signin', 'signout',
                'dashboard', 'panel', 'control', 'manager', 'config', 'configuration',
                'backup', 'backups', 'database', 'db', 'sql', 'mysql', 'postgres',
                'upload', 'uploads', 'download', 'downloads', 'images', 'img',
                'css', 'styles', 'js', 'javascript', 'api', 'rest', 'graphql',
                'test', 'testing', 'dev', 'development', 'staging', 'production',
                'tmp', 'temp', 'cache', 'backup', 'backups', 'archive', 'archives',
                'old', 'new', '2024', '2023', '2022', '2021', 'secret', 'hidden',
                'private', 'secure', 'auth', 'authentication', 'user', 'users',
                'account', 'accounts', 'profile', 'profiles', 'settings'
            ]
        }
        
        wordlist = wordlists.get(wordlist_size, wordlists['small'])
        extensions = ['', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.txt', '.bak', '.old']
        
        found_directories = []
        stats = {'tested': 0, 'found': 0}
        
        print(f"{Colors.MAGENTA}🎯 Bruteforcing with {len(wordlist)} words and {len(extensions)} extensions...{Colors.RESET}")
        
        def test_directory(path):
            for ext in extensions:
                test_path = f"{path}{ext}"
                stats['tested'] += 1
                
                try:
                    url = f"http://{target}/{test_path}"
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403]:
                        found_directories.append({
                            'path': test_path,
                            'status': response.status_code,
                            'size': len(response.content)
                        })
                        stats['found'] += 1
                        print(f"  {Colors.GREEN}✅ FOUND: /{test_path} (Status: {response.status_code}){Colors.RESET}")
                    else:
                        print(f"  {Colors.RED}❌ NOT FOUND: /{test_path}{Colors.RESET}", end='\r')
                
                except Exception as e:
                    print(f"  {Colors.YELLOW}⚠️  ERROR: /{test_path} - {e}{Colors.RESET}", end='\r')
        

        threads = []
        for word in wordlist:
            t = threading.Thread(target=test_directory, args=(word,))
            t.daemon = True
            t.start()
            threads.append(t)
            
            # Limit concurrent threads
            if len(threads) >= 10:
                for t in threads:
                    t.join()
                threads = []
        

        for t in threads:
            t.join()
        
        print(f"\n\n{Colors.GREEN}🎊 Directory Bruteforce Completed!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Scan Results:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Directories found: {stats['found']}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Directories tested: {stats['tested']}{Colors.RESET}")
        
        if found_directories:
            print(f"\n{Colors.CYAN}📋 Found Directories:{Colors.RESET}")
            for directory in found_directories:
                color = Colors.GREEN if directory['status'] == 200 else Colors.YELLOW if directory['status'] in [301, 302] else Colors.BLUE
                print(f"  {color}📁 /{directory['path']} - Status: {directory['status']} - Size: {directory['size']} bytes{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}⚠️  No directories found with the current wordlist{Colors.RESET}")