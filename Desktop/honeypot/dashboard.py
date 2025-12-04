from flask import Flask, render_template, jsonify
import json
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import os
import threading
import time

app = Flask(__name__)

LOG_FILE = 'honeypot.log'

# Cache for parsed data
cache = {
    'stats': None,
    'connections': None,
    'suspicious': None,
    'last_update': 0
}
CACHE_DURATION = 5  # seconds

# Background thread for cache updates
cache_lock = threading.Lock()

def parse_logs():
    """Parse honeypot logs and extract structured data."""
    connections = []
    suspicious_activities = []

    if not os.path.exists(LOG_FILE):
        return connections, suspicious_activities

    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                # Parse timestamp and message
                if ' - ' in line:
                    timestamp_str, message = line.strip().split(' - ', 1)
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

                    # Connection attempt
                    if 'Connection attempt from' in message and 'on port' in message:
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', message)
                        if ip_match:
                            ip = ip_match.group(1)
                            connections.append({
                                'timestamp': timestamp.isoformat(),
                                'ip': ip,
                                'type': 'connection'
                            })

                    # Payload received
                    elif 'Payload from' in message:
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                        if ip_match:
                            ip = ip_match.group(1)
                            # Extract HTTP method if present in payload
                            method_match = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', message)
                            method = method_match.group(1) if method_match else 'UNKNOWN'

                            connections.append({
                                'timestamp': timestamp.isoformat(),
                                'ip': ip,
                                'type': 'payload',
                                'method': method
                            })

                    # Suspicious activity
                    elif 'Suspicious activity detected' in message:
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                        if ip_match:
                            ip = ip_match.group(1)
                            suspicious_activities.append({
                                'timestamp': timestamp.isoformat(),
                                'ip': ip,
                                'type': 'suspicious'
                            })

                    # User-Agent logging
                    elif 'User-Agent from' in message:
                        # This is additional info, we can skip for now or store separately
                        pass

            except Exception as e:
                continue

    return connections, suspicious_activities

def update_cache():
    """Update the cache with fresh data."""
    connections, suspicious = parse_logs()

    # Total stats
    total_connections = len(connections)
    unique_ips = len(set(conn['ip'] for conn in connections))
    suspicious_count = len(suspicious)

    # IP frequency
    ip_counts = Counter(conn['ip'] for conn in connections)
    top_ips = [{'ip': ip, 'count': count} for ip, count in ip_counts.most_common(10)]

    # Method distribution
    methods = Counter(conn.get('method', 'UNKNOWN') for conn in connections if 'method' in conn)
    method_data = [{'method': method, 'count': count} for method, count in methods.items()]

    # Recent activity (last 24 hours)
    now = datetime.now()
    yesterday = now - timedelta(hours=24)
    recent_connections = [conn for conn in connections if datetime.fromisoformat(conn['timestamp']) > yesterday]
    recent_suspicious = [s for s in suspicious if datetime.fromisoformat(s['timestamp']) > yesterday]

    stats = {
        'total_connections': total_connections,
        'unique_ips': unique_ips,
        'suspicious_count': suspicious_count,
        'top_ips': top_ips,
        'method_distribution': method_data,
        'recent_connections': len(recent_connections),
        'recent_suspicious': len(recent_suspicious),
        'connections': connections[-50:],  # Last 50 connections
        'suspicious': suspicious[-20:]     # Last 20 suspicious activities
    }

    with cache_lock:
        cache['stats'] = stats
        cache['connections'] = connections[-100:]
        cache['suspicious'] = suspicious[-50:]
        cache['last_update'] = time.time()

def get_cached_data(key):
    """Get data from cache, updating if necessary."""
    current_time = time.time()
    with cache_lock:
        if cache['last_update'] == 0 or current_time - cache['last_update'] > CACHE_DURATION:
            update_cache()
        return cache[key]

def get_stats():
    """Get statistics from cache."""
    return get_cached_data('stats')

@app.route('/')
def dashboard():
    """Render the main dashboard."""
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics."""
    return jsonify(get_stats())

@app.route('/api/connections')
def api_connections():
    """API endpoint for recent connections."""
    return jsonify(get_cached_data('connections'))

@app.route('/api/suspicious')
def api_suspicious():
    """API endpoint for suspicious activities."""
    return jsonify(get_cached_data('suspicious'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
