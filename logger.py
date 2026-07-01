#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class LogHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging
    
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        log_msg = self.rfile.read(length).decode('utf-8')
        print(log_msg, flush=True)
        
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
    def do_GET(self):
        # Handle GET requests (often used to bypass strict browser policies)
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if 'log' in qs:
            print(qs['log'][0], flush=True)
            
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

print("Logger listening on port 8080... Waiting for PS5 connection.")
HTTPServer(('0.0.0.0', 8080), LogHandler).serve_forever()
