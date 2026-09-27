from __future__ import annotations

import socket
import time
import urllib.request

HOST = "127.0.0.1"
PORTS = [2222, 2323, 1883, 2121]

for i in range(15):
    try:
        urllib.request.urlopen(f"http://{HOST}:8080/admin", timeout=2).read()
    except Exception:
        pass
    for port in PORTS:
        try:
            with socket.create_connection((HOST, port), timeout=2) as s:
                try:
                    s.recv(1024)
                except Exception:
                    pass
                s.sendall(b"admin\n")
        except OSError:
            pass
    time.sleep(0.15)
print("Synthetic lab traffic sent to all honeypot ports.")
