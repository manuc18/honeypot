import socket
import logging

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 8080       # Port to listen on
LOG_FILE = 'honeypot.log'

# --- Setup Logging ---
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def start_honeypot(host, port):
    """Starts the honeypot listener."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[*] Honeypot listening on {host}:{port}...")
        logging.info(f"Honeypot started on {host}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                attacker_ip, attacker_port = addr
                log_message = f"Connection attempt from: {attacker_ip}:{attacker_port}"
                print(f"[!] {log_message}")
                logging.info(log_message)

                try:
                    conn.sendall(b"Welcome to the honeypot!\\n")
                except socket.error as e:
                    logging.error(f"Socket error: {e}")

                try:
                    data = conn.recv(1024)
                    if data:
                        payload = data.decode('utf-8', errors='ignore').strip()
                        log_payload = f"Received payload from {attacker_ip}: {payload}"
                        print(f"[+] {log_payload}")
                        logging.info(log_payload)
                except socket.error as e:
                    logging.error(f"Socket error receiving data: {e}")

if __name__ == "__main__":
    try:
        start_honeypot(HOST, PORT)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot.")
        logging.info("Honeypot shut down by user.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        logging.error(f"An unexpected error occurred: {e}")