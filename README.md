# Python Honeypot for Network Attack Analysis

This is a prototype for a Python-based honeypot designed to simluate common network services to lure,detect and log network connection attempts.

## How to Run

# 1. Start the Honeypot

Run the main script to start listening for connections on port 8080. All connection attempts will be logged to [honeypot.log](cci:7://file:///Users/manuchaudhary/Desktop/honeypot/honeypot.log:0:0-0:0).

```bash
python3 honeypot.py