import socket
import json
import urllib.request
import urllib.error
import time

for path, count in [("/health", 10), ("/login", 5), ("/admin", 1), ("/lab-attack", 1)]:
    for i in range(count):
        url = "http://10.20.0.10:8080" + path
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                result = {"path": path, "iteration": i+1, "status": response.status}
        except Exception as error:
            result = {"path": path, "iteration": i+1, "error": str(error)}
        print(json.dumps(result), flush=True)
        time.sleep(.04)
for port in range(20000, 20020):
    with socket.socket() as client:
        client.settimeout(.3)
        result = client.connect_ex(("10.20.0.10", port))
        print(json.dumps({"scan_port": port, "connect_ex": result}), flush=True)
