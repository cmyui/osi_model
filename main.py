#!/usr/bin/env python3.9
from enum import IntEnum, IntFlag
import socket
import struct
from dataclasses import dataclass
from typing import Optional

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


class EtherType(IntEnum):
    # https://en.wikipedia.org/wiki/EtherType#Values
    IPv4 = 0x0800
    ARP = 0x0806
    IPv6 = 0x86DD


@dataclass
class BasePacket:
    data_view: memoryview


@dataclass
class EthernetFrame(BasePacket):
    dst_mac: str
    src_mac: str
    ether_type: EtherType


def read_ethernet_frame(data_view: memoryview) -> EthernetFrame:
    """Read an ethernet frame from the given data."""

    dst_mac = data_view[:6].hex(":")
    src_mac = data_view[6:12].hex(":")

    # Values of 1500 and below mean that it is used to indicate the size of the
    # payload in octets, while values of 1536 and above indicate that it is used
    # as an EtherType
    funny_number = struct.unpack(">H", data_view[12:14])[0]

    if funny_number <= 1500:
        payload_length = funny_number
        assert payload_length == len(data_view) - 14
        ether_type = None
    else:
        ether_type = funny_number

    return EthernetFrame(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ether_type=EtherType(ether_type),
        data_view=data_view[14:],
    )


class SocketProtocols(IntEnum):
    # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    # TODO: this list is missing a lot of values from wikipedia
    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    IPIP = 4
    TCP = 6
    EGP = 8
    PUP = 12
    UDP = 17
    IDP = 22
    TP = 29
    IPV6 = 41
    ROUTING = 43
    FRAGMENT = 44
    RSVP = 46
    GRE = 47
    ESP = 50
    AH = 51
    ICMPV6 = 58
    NONE = 59
    DSTOPTS = 60
    PIM = 103
    SCTP = 132
    UDPLITE = 136
    WESP = 141
    RAW = 255


class IPv4Flags(IntFlag):
    RESERVED = 0
    DONT_FRAGMENT = 1 << 0
    MORE_FRAGMENTS = 1 << 1


@dataclass
class IPv4Packet(BasePacket):
    differentiated_services_code_point: int
    explicit_congestion_notification: int
    total_length: int
    identification: int
    flags: IPv4Flags
    fragment_offset: int
    time_to_live: int
    protocol: SocketProtocols
    header_checksum: int
    src_ip: str
    dest_ip: str


def read_ipv4_packet(data_view: memoryview) -> IPv4Packet:
    assert ((data_view[0] & 0b11110000) >> 4) == 4
    header_length = data_view[0] & 0b00001111

    dscp_ecn = data_view[1]
    total_length, identification = struct.unpack(">HH", data_view[2:6])

    flags = IPv4Flags((data_view[6] & 0b11100000) >> 5)
    fragment_offset = ((data_view[6] & 0b00011111) << 8) | data_view[7]

    time_to_live = data_view[8]
    protocol = SocketProtocols(data_view[9])
    header_checksum = struct.unpack(">H", data_view[10:12])[0]

    src_ip = socket.inet_ntoa(data_view[12:16])
    dest_ip = socket.inet_ntoa(data_view[16:20])

    if header_length != 5:
        # TODO: options

        ...

    return IPv4Packet(
        data_view=data_view[20:],
        differentiated_services_code_point=(dscp_ecn & 0b11111100) >> 2,
        explicit_congestion_notification=dscp_ecn & 0b00000011,
        total_length=total_length,
        identification=identification,
        flags=flags,
        fragment_offset=fragment_offset,
        time_to_live=time_to_live,
        protocol=protocol,
        header_checksum=header_checksum,
        src_ip=src_ip,
        dest_ip=dest_ip,
    )


def read_arp_packet(data_view: memoryview):
    ...


class TCPFlags(IntFlag):
    NS = 1 << 1
    CWR = 1 << 2
    ECE = 1 << 3
    URG = 1 << 4
    ACK = 1 << 5
    PSH = 1 << 6
    RST = 1 << 7
    SYN = 1 << 8
    FIN = 1 << 9


@dataclass
class TCPPacket(BasePacket):
    src_port: int  # u16
    dest_port: int  # u16
    sequence_number: int  # u32
    acknowledgement_number: int  # u32
    data_offset: int  # u4
    # reserved: int  # u3
    flags: TCPFlags  # u12
    window_size: int  # u32
    checksum: int  # u32
    urgent_pointer: Optional[int]  # u32

    # TODO: options


def read_tcp_packet(data_view: memoryview):
    src_port = struct.unpack(">H", data_view[0:2])[0]
    dest_port = struct.unpack(">H", data_view[2:4])[0]
    sequence_number = struct.unpack(">I", data_view[4:8])[0]
    acknowledgement_number = struct.unpack(">I", data_view[8:12])[0]
    data_offset = (data_view[12] & 0b11110000) >> 4
    reserved = (data_view[12] & 0b00001110) >> 1
    assert reserved == 0
    flags = TCPFlags(((data_view[12] & 0b00000001) << 8) | data_view[13])
    window_size = struct.unpack(">H", data_view[14:16])[0]
    checksum = struct.unpack(">H", data_view[16:18])[0]

    if flags & TCPFlags.URG:
        urgent_pointer = struct.unpack(">H", data_view[18:20])[0]
        header_end = 20
    else:
        urgent_pointer = None
        header_end = 18

    if data_offset > 5:
        # TODO: options
        ...

    return TCPPacket(
        data_view=data_view[header_end:],
        src_port=src_port,
        dest_port=dest_port,
        sequence_number=sequence_number,
        acknowledgement_number=acknowledgement_number,
        data_offset=data_offset,
        # reserved=reserved,
        flags=flags,
        window_size=window_size,
        checksum=checksum,
        urgent_pointer=urgent_pointer,
    )


@dataclass
class UDPPacket(BasePacket):
    src_port: int
    dest_port: int
    length: int
    checksum: int


def read_udp_packet(data_view: memoryview):
    return UDPPacket(
        src_port=struct.unpack(">H", data_view[0:2])[0],
        dest_port=struct.unpack(">H", data_view[2:4])[0],
        length=struct.unpack(">H", data_view[4:6])[0],
        checksum=struct.unpack(">H", data_view[6:8])[0],
        data_view=data_view[8:],
    )


def read_icmp_packet(data_view: memoryview):
    ...


def read_dns_packet(data_view: memoryview):
    ...


def read_http_packet(data_view: memoryview):
    ...


# def read_tls_packet(data_view: memoryview):
#     ...


def main() -> int:
    with socket.socket(
        family=socket.PF_PACKET,
        type=socket.SOCK_RAW,
        proto=socket.htons(ETH_P_ALL),  # accept all ethernet packets
    ) as sock:
        sock.bind(("eth0", 0))  # bind to network device

        while True:
            data = sock.recv(9000)
            if len(data) == 9000:
                # max size of a normal frame is 1500 bytes
                # max size of a jumbo frame is 9000 bytes
                breakpoint()

            # parse the network stack from this request
            with memoryview(data) as data_view:
                ethernet_frame = read_ethernet_frame(data_view)
                print(ethernet_frame)

                if ethernet_frame.ether_type == EtherType.IPv4:
                    ipv4_packet = read_ipv4_packet(ethernet_frame.data_view)
                    print(ipv4_packet)

                    if ipv4_packet.protocol == SocketProtocols.TCP:
                        tcp_packet = read_tcp_packet(ipv4_packet.data_view)
                        print(tcp_packet)
                    elif ipv4_packet.protocol == SocketProtocols.UDP:
                        udp_packet = read_udp_packet(ipv4_packet.data_view)
                        print(udp_packet)
                    elif ipv4_packet.protocol == SocketProtocols.ICMP:
                        icmp_packet = read_icmp_packet(ipv4_packet.data_view)
                        print(icmp_packet)
                    else:
                        print(f"non-implemented ipv4 protocol: {ipv4_packet.protocol}")
                elif ethernet_frame.ether_type == EtherType.ARP:
                    print("reading arp packet")
                else:
                    print(
                        f"non-implemented ethernet protocol: {ethernet_frame.ether_type}"
                    )

            print()  # \n

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
