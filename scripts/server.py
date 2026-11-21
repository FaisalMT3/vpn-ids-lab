from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        record = {"time": datetime.now(timezone.utc).isoformat(),
                  "client": self.client_address[0], "path": self.path}
        print(json.dumps(record), flush=True)
        payload = b"Isolated VPN/IDS lab: request received.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass

server = ThreadingHTTPServer(("10.20.0.10", 8080), Handler)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
