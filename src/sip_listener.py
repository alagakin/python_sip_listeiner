import socket
from typing import Optional, List

from packet_listener import ethernet_head, ipv4_head
from multiprocessing import Queue


def parse_sip(packet) -> Optional[List[bytes]]:
    if b'sip' in packet[6] and packet[3] == 6:
        sip_body = packet[6].split(b"\r\n")
        result = list()
        for index, row in enumerate(sip_body):
            if index == 0:
                result.append(row[32:])
            else:
                result.append(row)
        return result
    return None


def listener(packet_queue: Queue):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        packet = ipv4_head(eth[3])

        sip_packet = parse_sip(packet)

        if sip_packet is not None:
            packet_queue.put(sip_packet)
