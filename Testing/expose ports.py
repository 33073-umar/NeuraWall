import socket
import threading
import random

# List of sample responses for simulated services
def handle_client(client_socket, service_name):
    try:
        if service_name == "HTTP":
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>HTTP Service</h1>"
        elif service_name == "FTP":
            response = b"220 Welcome to Fake FTP Server\r\n"
        elif service_name == "SSH":
            response = b"SSH-2.0-OpenSSH_8.0\r\n"
        elif service_name == "DNS":
            response = b"\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
        else:
            response = b"Unknown Service\r\n"

        client_socket.send(response)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Function to start a service listener on a specific port
def start_service(port, service_name):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"{service_name} service started on port {port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Connection received on port {port} from {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket, service_name))
        thread.start()

# Define random ports and services
services = [
    {"port": random.randint(1024, 65535), "name": "HTTP"},
    {"port": random.randint(1024, 65535), "name": "FTP"},
    {"port": random.randint(1024, 65535), "name": "SSH"},
    {"port": random.randint(1024, 65535), "name": "DNS"}
]

# Start multiple simulated services
def run_services():
    threads = []
    for service in services:
        t = threading.Thread(target=start_service, args=(service["port"], service["name"]))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

if __name__ == "__main__":
    run_services()
