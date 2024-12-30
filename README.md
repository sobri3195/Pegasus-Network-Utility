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

### Network Packet Capture

The following script demonstrates network packet capture using `scapy`:

```python
from scapy.all import sniff, wrpcap

def packet_callback(packet):
    """Callback function to process captured packets."""
    print(f"Packet captured: {packet.summary()}")
    return packet

def capture_packets(interface, output_file, packet_count=100):
    """
    Capture packets on a specified interface and save them to a file.

    :param interface: Network interface to capture packets on.
    :param output_file: File to save the captured packets.
    :param packet_count: Number of packets to capture.
    """
    print(f"Starting packet capture on interface {interface}.")
    packets = sniff(iface=interface, count=packet_count, prn=packet_callback)
    print(f"Capture complete. Writing to {output_file}.")
    wrpcap(output_file, packets)

if __name__ == "__main__":
    # Example usage
    network_interface = "eth0"  # Replace with your interface name
    output_pcap = "network_capture.pcap"
    packet_limit = 50

    capture_packets(network_interface, output_pcap, packet_limit)
```

## Function Descriptions

#### `vnc_authenticate(server_ip, port=5900, username=None, password=None)`
Simulates VNC authentication, including basic handshake and optional username/password authentication.

#### `capture_packets(interface, output_file, packet_count=100)`
Captures network packets on a specified interface and saves them in `.pcap` format for further analysis.

## Example Scenarios

1. **Simulated VNC Handshake:** Test and simulate a basic VNC handshake for debugging and learning purposes.
2. **Network Packet Analysis:** Capture and analyze network traffic for troubleshooting and security research.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

For any inquiries or contributions, please contact Muhammad Sobri Maulana at [muhammadsobrimaulana31@gmail.com](mailto:muhammadsobrimaulana31@gmail.com).
