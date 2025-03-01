#!/usr/bin/env python3
import socket
import argparse
import struct
import binascii
import sys

def create_parser():
    parser = argparse.ArgumentParser(description='SOCKS5 Test Tool')
    parser.add_argument('-s', required=True, help='SOCKS5_HOST:SOCKS5_PORT')
    parser.add_argument('-u', help='Username for authentication')
    parser.add_argument('-p', help='Password for authentication')
    return parser

def test_tcp(host, port, username=None, password=None):
    try:
        print("Info:\t Testing TCP")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # SOCKS5 handshake
        if username and password:
            sock.send(bytes([0x05, 0x01, 0x02]))
        else:
            sock.send(bytes([0x05, 0x01, 0x00]))

        resp = sock.recv(2)
        if resp[0] != 0x05:
            print("Error:\t server is not socks version 5")
            return False
        if resp[1] != (0x02 if username and password else 0x00):
            print("Error:\t server does not support method", 0x02 if username and password else 0x00)
            return False

        # Authentication if required
        if username and password:
            auth = bytes([0x01, len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
            sock.send(auth)
            resp = sock.recv(2)
            if resp[1] != 0x00:
                print("Error:\t invalid username or password")
                return False

        # Connect to DNS server
        sock.send(bytes([0x05, 0x01, 0x00, 0x01, 0x08, 0x08, 0x08, 0x08, 0x00, 0x35]))
        resp = sock.recv(4)
        if resp[1] != 0x00:
            print("Error:\t Rep is not success")
            return False

        # Handle different address types
        if resp[3] == 0x01:  # IPv4
            sock.recv(6)
        elif resp[3] == 0x04:  # IPv6
            print("Error:\t This script does not support IPv6")
            return False
        elif resp[3] == 0x03:  # Domain name
            length = sock.recv(1)[0]
            sock.recv(length + 2)

        # Send DNS query
        dns_query = binascii.unhexlify('00200001010000010000000000000a74787468696e6b696e6703636f6d0000010001')
        sock.send(dns_query)
        response = sock.recv(65507)
        
        # For TCP DNS, first 2 bytes are length field, skip them
        dns_response = response[2:] if len(response) > 2 else response
        
        # Check DNS response
        if len(dns_response) >= 12:  # DNS header is 12 bytes
            dns_header = dns_response[:12]
            if (dns_header[2] & 0x80) == 0x80:
                print("OK:\t TCP DNS response received successfully")
            else:
                print("Warning:\t TCP response is not a valid DNS response")
        else:
            print("Warning:\t TCP response too short for DNS header")

        sock.close()
        return True

    except Exception as e:
        print("Error:\t", str(e))
        return False

def test_udp(host, port, username=None, password=None):
    try:
        print("Info:\t Testing UDP")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # SOCKS5 handshake (same as TCP)
        if username and password:
            sock.send(bytes([0x05, 0x01, 0x02]))
        else:
            sock.send(bytes([0x05, 0x01, 0x00]))

        resp = sock.recv(2)
        if resp[0] != 0x05:
            print("Error:\t server is not socks version 5")
            return False
        if resp[1] != (0x02 if username and password else 0x00):
            print("Error:\t server does not support method", 0x02 if username and password else 0x00)
            return False

        # Authentication if required
        if username and password:
            auth = bytes([0x01, len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
            sock.send(auth)
            resp = sock.recv(2)
            if resp[1] != 0x00:
                print("Error:\t invalid username or password")
                return False

        # Request UDP association
        sock.send(bytes([0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        resp = sock.recv(4)
        if resp[1] != 0x00:
            print("Error:\t Rep is not success")
            return False

        # Get UDP relay address
        udp_host = None
        udp_port = None
        
        if resp[3] == 0x01:  # IPv4
            addr_bytes = sock.recv(4)
            udp_host = '.'.join(str(b) for b in addr_bytes)
            port_bytes = sock.recv(2)
            udp_port = struct.unpack('!H', port_bytes)[0]
        elif resp[3] == 0x04:  # IPv6
            print("Error:\t This script does not support IPv6")
            return False
        elif resp[3] == 0x03:  # Domain name
            length = sock.recv(1)[0]
            udp_host = sock.recv(length).decode()
            port_bytes = sock.recv(2)
            udp_port = struct.unpack('!H', port_bytes)[0]

        # Create UDP socket
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(('0.0.0.0', 0))

        # Send DNS query over UDP
        dns_query = binascii.unhexlify('000000010808080800350001010000010000000000000a74787468696e6b696e6703636f6d0000010001')
        udp_sock.sendto(dns_query, (udp_host, udp_port))

        # Receive response
        response, _ = udp_sock.recvfrom(65507)
        
        # For UDP SOCKS5, first 10 bytes are SOCKS5 header, skip them
        dns_response = response[10:] if len(response) > 10 else response
        
        # Check DNS response
        if len(dns_response) >= 12:  # DNS header is 12 bytes
            dns_header = dns_response[:12]
            if (dns_header[2] & 0x80) == 0x80:
                print("OK:\t UDP DNS response received successfully")
            else:
                print("Warning:\t UDP response is not a valid DNS response")
        else:
            print("Warning:\t UDP response too short for DNS header")

        udp_sock.close()
        sock.close()
        return True

    except Exception as e:
        print("Error:\t", str(e))
        return False

def main():
    parser = create_parser()
    args = parser.parse_args()

    # Parse SOCKS5 server address
    try:
        host, port = args.s.split(':')
        port = int(port)
    except:
        print("Invalid socks5 server")
        sys.exit(1)

    # Run tests
    tcp_result = test_tcp(host, port, args.u, args.p)
    udp_result = test_udp(host, port, args.u, args.p)

    if not tcp_result or not udp_result:
        sys.exit(1)

if __name__ == "__main__":
    main()