import socket
import logging
import re
import threading
import time
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import defaultdict, deque

# --- Enhanced Configuration ---
HOST = '0.0.0.0'
PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    993: 'IMAPS',
    995: 'POP3S',
    8080: 'HTTP-ALT',
    8443: 'HTTPS-ALT'
}

LOG_FILE = 'honeypot.log'
JSON_LOG_FILE = 'honeypot_events.json'
ATTACK_LOG_FILE = 'attacks_detected.log'
MAX_WORKERS = 20  # Increased for robustness
CONNECTION_TIMEOUT = 30  # seconds
MAX_CONNECTIONS_PER_IP = 50  # Rate limiting
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  # For future geolocation

# --- Attack Classification ---
ATTACK_TYPES = {
    'sql_injection': ['union.*select', 'select.*from.*where', 'drop.*table', 'insert.*into'],
    'xss': ['<script>', 'javascript:', 'onload=', 'onerror=', 'alert\\('],
    'directory_traversal': ['\\.\\./', '\\.\\./', '/etc/passwd', '/etc/shadow'],
    'command_injection': ['\\|\\|', '&&', ';', '`', '\\$\\('],
    'buffer_overflow': ['%[0-9a-fA-F]{2}', '0x[0-9a-fA-F]+'],
    'brute_force': ['admin.*admin', 'root.*root', 'test.*test'],
    'scanner': ['nmap', 'masscan', 'nikto', 'dirbuster', 'gobuster'],
    'exploit': ['shellshock', 'heartbleed', 'eternalblue', 'wannacry']
}

# --- Setup Logging ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Global State Management ---
connection_tracker = defaultdict(list)  # IP -> list of connection records
attack_database = deque(maxlen=10000)   # Keep last 10k attacks in memory
rate_limits = defaultdict(deque)        # IP -> deque of timestamps

def classify_attack(payload):
    """Classify the type of attack based on payload patterns."""
    payload_lower = payload.lower()

    for attack_type, patterns in ATTACK_TYPES.items():
        for pattern in patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                return attack_type

    # Additional heuristic-based classification
    if len(payload) > 1000:
        return 'buffer_overflow'
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', payload):
        return 'scanner'
    if any(char in payload for char in ['<', '>', '"', "'"]):
        return 'injection_attempt'

    return 'unknown'

def check_rate_limit(ip):
    """Implement rate limiting to prevent DoS attacks."""
    current_time = time.time()
    timestamps = rate_limits[ip]

    # Clean old entries (older than 1 minute)
    while timestamps and current_time - timestamps[0] > 60:
        timestamps.popleft()

    # Check if under limit
    if len(timestamps) >= MAX_CONNECTIONS_PER_IP:
        return False

    # Add current connection
    timestamps.append(current_time)
    return True

def log_attack_event(ip, port, attack_type, payload, confidence_score=0.0):
    """Log detailed attack information to JSON database."""
    event = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'port': port,
        'attack_type': attack_type,
        'payload_hash': hashlib.sha256(payload.encode()).hexdigest(),
        'payload_length': len(payload),
        'confidence_score': confidence_score,
        'service': PORTS.get(port, 'UNKNOWN'),
        'raw_payload': payload[:500] if len(payload) <= 500 else payload[:497] + '...'
    }

    attack_database.append(event)

    # Write to JSON log file
    try:
        with open(JSON_LOG_FILE, 'a') as f:
            json.dump(event, f)
            f.write('\n')
    except Exception as e:
        logging.error(f"Failed to write attack event: {e}")

    # Write to attack-specific log
    try:
        with open(ATTACK_LOG_FILE, 'a') as f:
            f.write(f"[{event['timestamp']}] {attack_type.upper()} from {ip}:{port} - {event['raw_payload'][:100]}\n")
    except Exception as e:
        logging.error(f"Failed to write attack log: {e}")

def is_malicious(payload):
    """Enhanced malicious payload detection with confidence scoring."""
    payload_lower = payload.lower()
    confidence_score = 0.0
    detected_patterns = []

    # Check against attack patterns
    for attack_type, patterns in ATTACK_TYPES.items():
        for pattern in patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                confidence_score += 0.3
                detected_patterns.append(f"{attack_type}:{pattern}")

    # Additional heuristics
    if len(payload) > 2000:
        confidence_score += 0.4  # Likely buffer overflow
    if len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', payload)) > 3:
        confidence_score += 0.3  # Multiple IPs suggest scanning
    if any(keyword in payload_lower for keyword in ['union', 'select', 'script', 'bash', 'wget']):
        confidence_score += 0.2

    # Entropy check (high entropy suggests encoded data)
    entropy = calculate_entropy(payload)
    if entropy > 5.0:
        confidence_score += 0.2

    return confidence_score > 0.5, confidence_score, detected_patterns

def calculate_entropy(text):
    """Calculate Shannon entropy of text (higher = more random/complex)."""
    if not text:
        return 0

    import math
    entropy = 0
    for char in set(text):
        p = float(text.count(char)) / len(text)
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy

def extract_http_info(data):
    """Extract HTTP request information."""
    info = {
        'method': 'UNKNOWN',
        'path': '/',
        'user_agent': None,
        'headers': {}
    }

    try:
        lines = data.split('\n')
        if lines:
            # Parse request line
            request_line = lines[0].strip()
            parts = request_line.split()
            if len(parts) >= 2:
                info['method'] = parts[0]
                info['path'] = parts[1]

            # Parse headers
            for line in lines[1:]:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    info['headers'][key] = value

                    if key == 'user-agent':
                        info['user_agent'] = value

    except Exception:
        pass

    return info

def generate_response(service_type, http_info=None, is_suspicious=False):
    """Generate appropriate response based on service type."""
    if service_type == 'HTTP':
        if is_suspicious:
            return (
                # Block suspicious
                "HTTP/1.1 403 Forbidden\r\n"  
                "Content-Type: text/html\r\n"
                "Connection: close\r\n\r\n"
                "<html><body><h1>403 Forbidden</h1><p>Access Denied</p></body></html>"
            )
        else:
            return (
                # Normal response
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Server: Apache/2.4.41 (Ubuntu)\r\n"
                "Connection: close\r\n\r\n"
                "<!DOCTYPE html><html><head><title>Welcome</title></head><body>"
                "<h1>Welcome to our web server!</h1><p>This is a honeypot system.</p>"
                "</body></html>"
            )

    elif service_type == 'FTP':
        return "220 Welcome to FTP server\r\n"

    elif service_type == 'SSH':
        return "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"

    return "Welcome to honeypot\r\n"

def handle_connection(conn, addr, port):
    """Enhanced connection handler with sophisticated detection and logging."""
    client_ip, client_port = addr
    service_type = PORTS.get(port, 'UNKNOWN')
    connection_id = f"{client_ip}:{client_port}"
    start_time = time.time()

    try:
        # Rate limiting check
        if not check_rate_limit(client_ip):
            logging.warning(f"Rate limit exceeded for {client_ip}")
            conn.close()
            return

        # Set socket timeout
        conn.settimeout(CONNECTION_TIMEOUT)

        # Log connection attempt with enhanced tracking
        log_message = f"Connection attempt from {connection_id} on port {port} ({service_type})"
        print(f"[!] {log_message}")
        logging.info(log_message)

        # Track connection in global state
        connection_tracker[client_ip].append({
            'port': port,
            'timestamp': datetime.now(),
            'service': service_type
        })

        # Receive data with enhanced error handling
        try:
            data = conn.recv(4096)
            if not data:
                return
        except socket.timeout:
            logging.info(f"Connection timeout from {connection_id}")
            return
        except socket.error as e:
            logging.error(f"Socket error from {connection_id}: {e}")
            return

        payload = data.decode('utf-8', errors='ignore').strip()

        # Parse HTTP if it's an HTTP service
        http_info = None
        if 'HTTP' in service_type:
            http_info = extract_http_info(payload)

        # Enhanced malicious detection with confidence scoring
        is_suspicious, confidence_score, detected_patterns = is_malicious(payload)
        attack_type = classify_attack(payload) if is_suspicious else 'benign'

        # Log payload details with enhanced information
        if payload:
            payload_log = f"Payload from {connection_id}: {payload[:200]}{'...' if len(payload) > 200 else ''}"
            print(f"[+] {payload_log}")
            logging.info(payload_log)

            if http_info and http_info['user_agent']:
                logging.info(f"User-Agent from {connection_id}: {http_info['user_agent']}")

            # Log additional metadata
            logging.info(f"Metadata for {connection_id}: length={len(payload)}, entropy={calculate_entropy(payload):.2f}")

        # Enhanced suspicious activity logging
        if is_suspicious:
            suspicious_log = f"🚨 ATTACK DETECTED: {attack_type.upper()} from {connection_id} (confidence: {confidence_score:.2f})"
            print(f"[🚨] {suspicious_log}")
            logging.warning(suspicious_log)

            # Log detailed attack information
            log_attack_event(client_ip, port, attack_type, payload, confidence_score)

            if detected_patterns:
                logging.warning(f"Detected patterns for {connection_id}: {', '.join(detected_patterns)}")

        # Generate context-aware response
        response = generate_response(service_type, http_info, is_suspicious)

        # Send response with error handling
        try:
            conn.sendall(response.encode())
        except socket.error as e:
            logging.error(f"Failed to send response to {connection_id}: {e}")

        # Simulate realistic processing time
        processing_time = time.time() - start_time
        if processing_time < 0.05:  # Minimum processing time for realism
            time.sleep(0.05 - processing_time)

    except Exception as e:
        logging.error(f"Critical error handling connection from {connection_id}: {str(e)}")
        print(f"[!] Error with {connection_id}: {str(e)}")
    finally:
        # Enhanced cleanup
        try:
            conn.close()
        except:
            pass

        # Log connection duration
        duration = time.time() - start_time
        logging.info(f"Connection closed: {connection_id} (duration: {duration:.2f}s)")

        # Clean up old connection tracking (keep last 1000 entries per IP)
        if client_ip in connection_tracker:
            connection_tracker[client_ip] = connection_tracker[client_ip][-1000:]

def start_honeypot_server(host, port, service_type):
    """Start honeypot server for specific port and service."""
    def server_loop():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((host, port))
                server_socket.listen(5)
                print(f"[*] {service_type} honeypot listening on {host}:{port}")

                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    while True:
                        try:
                            conn, addr = server_socket.accept()
                            # Submit connection handling to thread pool
                            executor.submit(handle_connection, conn, addr, port)
                        except KeyboardInterrupt:
                            break
                        except Exception as e:
                            logging.error(f"Error accepting connection on port {port}: {e}")

            except Exception as e:
                print(f"[!] Failed to start {service_type} server on port {port}: {e}")
                logging.error(f"Server error on port {port}: {e}")

    # Start server in background thread
    server_thread = threading.Thread(target=server_loop, daemon=True)
    server_thread.start()
    return server_thread

def main():
    """Main function to start all honeypot services."""
    print("🍯 Starting Python Honeypot System")
    print("=" * 50)
    logging.info("Honeypot system starting up")

    threads = []

    # Start honeypot servers for each configured port
    for port, service_type in PORTS.items():
        thread = start_honeypot_server(HOST, port, service_type)
        threads.append(thread)
        time.sleep(0.1)  # Small delay between starting servers

    print(f"\n[*] All honeypot services started. Listening on ports: {list(PORTS.keys())}")
    print("[*] Press Ctrl+C to stop")

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot system...")
        logging.info("Honeypot system shutting down")
        print("[*] Shutdown complete")

if __name__ == "__main__":
    main()
