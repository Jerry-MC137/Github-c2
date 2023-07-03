import socket
import os

# host to listen on
HOST = '192.168.100.2'

def main():
    # CREATE RAW SOCKET, BIN TO PUBLIC INTERFACE
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    #INCLUDE THE IP HEADER IN CAPTURE
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #READ ONE PACKET
    print(sniffer.recvfrom(65565))

    # IF WE'RE ON WINDOWS TURN OFF PROMISCUOUS MODE
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()