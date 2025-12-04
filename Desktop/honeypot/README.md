# 🔥 Python Honeypot for Network Attack Analysis & Monitoring

## 📋 Capstone Project Overview

This is a comprehensive Python-based honeypot system designed for network attack detection, analysis, and real-time monitoring. The system implements multiple service simulations (HTTP, FTP, SSH) with advanced multithreading capabilities, robust error handling, and a beautiful analytics dashboard.

## 🎯 Key Features

### 🔒 Honeypot Core
- **Multithreaded Architecture**: Handles multiple concurrent connections using ThreadPoolExecutor
- **Multiple Service Simulation**: HTTP (ports 80, 8080), FTP (port 21), SSH (port 22)
- **Advanced Threat Detection**: Sophisticated pattern matching for SQL injection, XSS, directory traversal, and common attack tools
- **Realistic Responses**: Service-appropriate responses to maintain deception
- **Robust Error Handling**: Graceful handling of network errors, timeouts, and connection issues

### 📊 Analytics Dashboard
- **Real-time Monitoring**: Live statistics with auto-refresh every 30 seconds
- **Interactive Charts**: Bar charts for top attacking IPs, doughnut charts for HTTP method distribution
- **Comprehensive Statistics**: Total connections, unique IPs, suspicious activities, recent activity
- **Beautiful UI**: Modern design with Bootstrap, Font Awesome icons, and smooth animations
- **Responsive Design**: Works perfectly on desktop and mobile devices

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Attacker      │───▶│   Honeypot       │───▶│   Log File      │
│   Connections   │    │   Services       │    │   (honeypot.log)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Flask API      │───▶│   Dashboard     │
                       │   Backend        │    │   Frontend      │
                       └──────────────────┘    └─────────────────┘
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- pip package manager

### Installation
```bash
# Clone or navigate to the project directory
cd /Users/manuchaudhary/Desktop/honeypot

# Install dependencies
pip install -r requirements.txt
```

## 🎮 Usage

### 1. Start the Honeypot
```bash
python3 honeypot.py
```

The honeypot will start listening on multiple ports:
- **Port 80**: HTTP service
- **Port 21**: FTP service
- **Port 22**: SSH service
- **Port 8080**: HTTP-ALT service (if available)

### 2. Start the Analytics Dashboard
```bash
python3 dashboard.py
```

Access the dashboard at: **http://localhost:5001**

### 3. Monitor Logs
All activities are logged to `honeypot.log` with timestamps and detailed information.

## 📈 Dashboard Features

### Statistics Cards
- **Total Connections**: All connection attempts
- **Unique IPs**: Distinct attacking IP addresses
- **Suspicious Activities**: Detected malicious attempts
- **Recent Activity**: Connections in the last 24 hours

### Charts & Visualizations
- **Top Attacking IPs**: Bar chart showing most active attackers
- **HTTP Methods**: Distribution of HTTP request methods
- **Real-time Tables**: Live updates of recent connections and suspicious activities

### Real-time Updates
- Auto-refresh every 30 seconds
- Manual refresh button
- Live status indicators

## 🔍 Detection Capabilities

### Attack Patterns Detected
- **SQL Injection**: UNION SELECT, DROP TABLE, etc.
- **Cross-Site Scripting (XSS)**: Script tags, alert functions
- **Directory Traversal**: ../../../etc/passwd patterns
- **Command Injection**: Shell commands and system exploits
- **Buffer Overflow**: URL-encoded attack patterns

### Service-Specific Responses
- **HTTP**: Realistic web server responses with proper headers
- **FTP**: Standard FTP welcome messages
- **SSH**: OpenSSH version banners

## 🛡️ Security Features

- **Timeout Handling**: 10-second connection timeouts
- **Resource Management**: Proper socket cleanup and error handling
- **Thread Safety**: ThreadPoolExecutor for concurrent connections
- **Input Validation**: Comprehensive payload sanitization
- **Logging**: Detailed logging with timestamps and IP tracking

## 📝 Logging Format

```
2025-12-02 17:31:15 - Connection attempt from 192.168.1.100:54321 on port 80 (HTTP)
2025-12-02 17:31:15 - Payload from 192.168.1.100: GET / HTTP/1.1
2025-12-02 17:31:15 - Suspicious activity detected from 192.168.1.100: malicious payload...
```

## 🧪 Testing

### Manual Testing
```bash
# Test HTTP connection
curl http://localhost:80

# Test FTP connection
telnet localhost 21

# Test SSH connection
ssh localhost
```

### Automated Testing
The system includes comprehensive error handling and has been tested with:
- Normal web requests
- Malicious payload injection
- Concurrent connections
- Network interruptions

## 📚 Project Deliverables

### ✅ Completed Features
- [x] Multithreaded honeypot with ThreadPoolExecutor
- [x] Multiple service simulations (HTTP, FTP, SSH)
- [x] Advanced threat detection patterns
- [x] Robust error handling and logging
- [x] Real-time analytics dashboard
- [x] Interactive charts and visualizations
- [x] Responsive web interface
- [x] Comprehensive documentation

### 🎯 Capstone Requirements Met
- **Phase 1**: Research & Design ✓
- **Phase 2**: Core Implementation ✓
- **Phase 3**: Logging & Analysis ✓
- **Phase 4**: Testing & Documentation ✓

## 🏆 Technical Highlights

### Code Quality
- Clean, maintainable Python code
- Modular architecture with separation of concerns
- Comprehensive error handling
- Well-documented functions and classes

### Performance
- Handles up to 10 concurrent connections per service
- Efficient log parsing and analysis
- Optimized dashboard updates

### Security
- Realistic service simulation
- Comprehensive attack pattern detection
- Secure logging practices

## 🔄 Future Enhancements

- **Machine Learning**: AI-powered threat classification
- **Database Integration**: Persistent storage for long-term analysis
- **Alert System**: Email/SMS notifications for suspicious activities
- **Geolocation**: IP geolocation and mapping
- **Advanced Analytics**: Trend analysis and predictive modeling

## 📞 Support

For questions or issues, please check the logs in `honeypot.log` and ensure all dependencies are properly installed.

---

**🎓 Computer Networks Capstone Project - Network Attack Prevention & Analysis**
