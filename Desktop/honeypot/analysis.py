import re

LOG_FILE = 'honeypot.log'

def run_analysis():
    """Reads the log file and provides a baseline analysis."""
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{LOG_FILE}' not found. Run the honeypot first.")
        return

    connection_count = 0
    unique_ips = set()
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for line in lines:
        if "Connection attempt from" in line:
            connection_count += 1
            match = ip_pattern.search(line)
            if match:
                unique_ips.add(match.group(1))

    print(f"Total Connection Attempts Logged: {connection_count}")
    print(f"Number of Unique Source IPs: {len(unique_ips)}")
    if unique_ips:
        print("IPs Observed:")
        for ip in sorted(list(unique_ips)):
            print(f"- {ip}")

if __name__ == "__main__":
    run_analysis()