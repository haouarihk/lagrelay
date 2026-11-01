#!/usr/bin/env python3
"""Fake game server: UDP echo that reports the sender's IP, plus a TCP bulk download."""
import socket, socketserver, threading

BLOB = bytes((i * 31) & 0xFF for i in range(1 << 16)) * 320  # 20 MiB

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 9000))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(a[0].encode() + b"|" + d, a)

class H(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(BLOB)

threading.Thread(target=udp, daemon=True).start()
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", 9001), H).serve_forever()
