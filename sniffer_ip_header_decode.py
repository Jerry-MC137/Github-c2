import ipaddress
import os
import socket
import struct
import sys


class IP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # HUMAN READABLE IP ADDRESSES
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_addres = ipaddress.ip_address(self.dst)

        # MAP PROTOCOL CONSTANTS TO THEIR NAMES
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

    @staticmethod
    def sniff(host):
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET,
                                socket.SOCK_RAW, socket_protocol)

        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        try:
            while True:
                # READ PACKET
                raw_buffer = sniffer.recvfrom(65535)[0]
                # CREATE AN IP HEADER FROM THE FIRST 20 BYTES
                ip_header = IP(raw_buffer[0:20])
                # PRINT THE DETECTED PROTOCOL AND HOSTS
                print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                                 ip_header.src_address,
                                                 ip_header.dst_addres))
        except KeyboardInterrupt:
            # IF WE'RE ON WINDOWS TURN OFF PROMISCUOUS MODE
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.100.2'
    IP.sniff(host)