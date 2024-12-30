# Pegasus Network Utility

**Author:** Muhammad Sobri Maulana  
**Email:** muhammadsobrimaulana31@gmail.com  

Pegasus Network Utility is a Python-based tool designed for network traffic capture, VNC authentication simulation, and basic packet analysis. This utility offers robust features for network engineers, security researchers, and system administrators to test and simulate various network scenarios.

## Features

- **VNC Authentication Simulation:** Simulates a handshake and authentication process with a VNC server.
- **Network Packet Capture:** Captures and processes network packets, saving them in `.pcap` format for analysis.

## Requirements

- Python 3.7+
- Libraries:
  - `scapy` for packet capture

Install the required library with:

```bash
pip install scapy
```

## Installation

Clone the repository and navigate to the project directory:

```bash
$ git clone https://github.com/your-repo/pegasus-network-utility.git
$ cd pegasus-network-utility
```

## Usage

### VNC Authentication Simulation

The following script demonstrates a simulated handshake and authentication process with a VNC server:

```python
import socket
import time

def vnc_authenticate(server_ip, port=5900, username=None, password=None):
    """
    Simulate VNC server authentication.
    
    :param server_ip: IP address of the VNC server.
    :param port: Port to connect to (default 5900).
    :param username: Optional username for authentication.
    :param password: Password for authentication.
    """
    try:
        print(f"Connecting to VNC server at {server_ip}:{port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as vnc_socket:
            vnc_socket.connect((server_ip, port))
            print("Connected to VNC server.")
            
            # Send RFB version handshake (example version: 003.003)
            vnc_socket.sendall(b"RFB 003.003\n")
            response = vnc_socket.recv(1024)
            print(f"Server response: {response.decode()}")
            
            # Simulate sending username/password if required
            if username and password:
                print(f"Authenticating with username: {username}")
                auth_data = f"{username}:{password}".encode()
                vnc_socket.sendall(auth_data)
                auth_response = vnc_socket.recv(1024)
                print(f"Authentication response: {auth_response.decode()}")
            else:
                print("No authentication provided.")
            
            # Simulate interaction
            print("Sending example interaction...")
            vnc_socket.sendall(b"ClientInit\n")
            server_message = vnc_socket.recv(1024)
            print(f"Server message: {server_message.decode()}")
    
    except Exception as e:
        print(f"Error during VNC connection: {e}")

if __name__ == "__main__":
    # Replace with your VNC server's IP and port
    vnc_server_ip = "192.168.8.130"
    vnc_server_port = 5900

    # Optionally provide username and password
    vnc_username = "admin"
    vnc_password = "password123"
    
    vnc_authenticate(vnc_server_ip, vnc_server_port, vnc_username, vnc_password)
```
