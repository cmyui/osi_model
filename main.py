#!/usr/bin/env python3.9
from enum import IntEnum, IntFlag
import socket
import struct
from dataclasses import dataclass
from typing import Optional

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


class BinaryReader:
    def __init__(self, data_view: memoryview) -> None:
        self.data_view = data_view

    def read_u8(self) -> int:
        val = self.data_view[0]
        self.data_view = self.data_view[1:]
        return val

    def read_u16(self) -> int:
        (val,) = struct.unpack(">H", self.data_view[:2])
        self.data_view = self.data_view[2:]
        return val

    def read_u32(self) -> int:
        (val,) = struct.unpack(">I", self.data_view[:4])
        self.data_view = self.data_view[4:]
        return val

    def read_u64(self) -> int:
        (val,) = struct.unpack(">Q", self.data_view[:8])
        self.data_view = self.data_view[8:]
        return val

    def read_bytes(self, length: int) -> bytes:
        val = self.data_view[:length].tobytes()
        self.data_view = self.data_view[length:]
        return val


class EtherType(IntEnum):
    # https://en.wikipedia.org/wiki/EtherType#Values
    IPv4 = 0x0800
    ARP = 0x0806
    IPv6 = 0x86DD


@dataclass
class BasePacket:
    data: bytes


@dataclass
class EthernetFrame(BasePacket):
    dst_mac: str
    src_mac: str
    ether_type: EtherType


def read_ethernet_frame(reader: BinaryReader) -> EthernetFrame:
    """Read an ethernet frame from the given data."""

    dst_mac = reader.read_bytes(6).hex(":")
    src_mac = reader.read_bytes(6).hex(":")

    # Values of 1500 and below mean that it is used to indicate the size of the
    # payload in octets, while values of 1536 and above indicate that it is used
    # as an EtherType
    ether_type_or_payload_length = reader.read_u16()
    if ether_type_or_payload_length <= 1500:
        payload_length = ether_type_or_payload_length
        ether_type = None
    else:
        ether_type = ether_type_or_payload_length

    return EthernetFrame(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ether_type=EtherType(ether_type),
        data=reader.data_view.tobytes(),
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


class IPv4OptionClass(IntEnum):
    CONTROL = 0
    # 1 is reserved
    DEBUGGING_AND_MEASUREMENT = 2
    # 3 is reserved


class IPv4OptionType(IntEnum):
    EOOL = 0  # End of Option List
    NOP = 1  # No Operation
    # SEC = 2  # Security (defunct)
    RR = 7  # Record Route
    ZSU = 10  # Experimental Measurement
    MTUP = 11  # MTU Probe
    MTUR = 12  # MTU Reply
    ENCODE = 15  # ENCODE
    QS = 25  # Quick-Start
    # TODO: why are all experiement ids referencing RFC3692?? wikipedia bug?
    # EXP = 30  # RFC3692-style Experiment
    TS = 68  # Time Stamp
    TR = 82  # Traceroute
    # EXP = 94  # RFC3692-style Experiment
    SEC = 130  # Security (RIPSO)
    LSR = 131  # Loose Source Route
    E = 133  # SEC	Extended Security (RIPSO)
    CIPSO = 134  # Commercial IP Security Option
    SID = 136  # Stream ID
    SSR = 137  # Strict Source Route
    VISA = 142  # Experimental Access Control
    IMITD = 144  # IMI Traffic Descriptor
    EIP = 145  # Extended Internet Protocol
    ADDEXT = 147  # Address Extension
    RTRALT = 148  # Router Alert
    SDB = 149  # Selective Directed Broadcast
    DPS = 151  # Dynamic Packet State
    UMP = 152  # Upstream Multicast Pkt.
    # EXP = 158  # RFC3692-style Experiment
    FINN = 205  # Experimental Flow Control
    # EXP = 222  # RFC3692-style Experiment


@dataclass
class IPv4Option:
    copied: bool
    class_: IPv4OptionClass
    type_: IPv4OptionType
    data: bytes


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

    options: list[IPv4Option]


def read_ipv4_packet(reader: BinaryReader) -> IPv4Packet:
    """\
    Read an internet protocol (version 4) packet.

    https://en.wikipedia.org/wiki/IPv4#Packet_structure
    """
    first_byte = reader.read_u8()
    assert ((first_byte & 0b11110000) >> 4) == 4
    header_length = first_byte & 0b00001111

    second_byte = reader.read_u8()
    differentiated_services_code_point = (second_byte & 0b11111100) >> 2
    explicit_congestion_notification = second_byte & 0b00000011

    total_length = reader.read_u16()
    identification = reader.read_u16()

    seventh_byte = reader.read_u8()
    eighth_byte = reader.read_u8()
    flags = IPv4Flags((seventh_byte & 0b11100000) >> 5)
    fragment_offset = ((seventh_byte & 0b00011111) << 8) | eighth_byte

    time_to_live = reader.read_u8()
    protocol = SocketProtocols(reader.read_u8())
    header_checksum = reader.read_u16()

    src_ip = socket.inet_ntoa(reader.read_bytes(4))
    dest_ip = socket.inet_ntoa(reader.read_bytes(4))

    options = []
    options_bytes_read = 0  # can probably be better
    while (options_bytes_read / 4) < (header_length - 5):
        byte = reader.read_u8()
        option_copied = ((byte & 0b10000000) >> 7) == 1
        option_class = IPv4OptionClass((byte & 0b01100000) >> 5)
        option_type = IPv4OptionType(byte & 0b00011111)  # aka option_number
        option_length = reader.read_u8()
        # TODO: assert length is ok
        option_data = reader.read_bytes(option_length)

        options_bytes_read += 2 + option_length

        options.append(
            IPv4Option(
                copied=option_copied,
                class_=option_class,
                type_=option_type,
                data=option_data,
            )
        )

        if option_type == IPv4OptionType.EOOL:
            # break out of the loop early
            break

    return IPv4Packet(
        data=reader.data_view.tobytes(),
        differentiated_services_code_point=differentiated_services_code_point,
        explicit_congestion_notification=explicit_congestion_notification,
        total_length=total_length,
        identification=identification,
        flags=flags,
        fragment_offset=fragment_offset,
        time_to_live=time_to_live,
        protocol=protocol,
        header_checksum=header_checksum,
        src_ip=src_ip,
        dest_ip=dest_ip,
        options=options,
    )


def read_arp_packet(reader: BinaryReader):
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
class TCPOption:
    ...


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

    options: list[TCPOption]


def read_tcp_packet(reader: BinaryReader) -> TCPPacket:
    src_port = reader.read_u16()
    dest_port = reader.read_u16()
    sequence_number = reader.read_u32()
    acknowledgement_number = reader.read_u32()

    eleventh_byte = reader.read_u8()
    twelth_byte = reader.read_u8()
    data_offset = (eleventh_byte & 0b11110000) >> 4
    reserved = (eleventh_byte & 0b00001110) >> 1
    assert reserved == 0
    flags = TCPFlags(((eleventh_byte & 0b00000001) << 8) | twelth_byte)

    window_size = reader.read_u16()
    checksum = reader.read_u16()

    if flags & TCPFlags.URG:
        urgent_pointer = reader.read_u16()
    else:
        urgent_pointer = None

    options = []
    if data_offset > 5:
        # TODO: options
        breakpoint()
        ...

    return TCPPacket(
        data=reader.data_view.tobytes(),
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
        options=options,
    )


@dataclass
class UDPPacket(BasePacket):
    src_port: int
    dest_port: int
    length: int
    checksum: int


def read_udp_packet(reader: BinaryReader) -> UDPPacket:
    return UDPPacket(
        src_port=reader.read_u16(),
        dest_port=reader.read_u16(),
        length=reader.read_u16(),
        checksum=reader.read_u16(),
        data=reader.data_view.tobytes(),
    )


def read_icmp_packet(reader: BinaryReader):
    ...


def read_dns_packet(reader: BinaryReader):
    ...


def read_http_packet(reader: BinaryReader):
    ...


# def read_tls_packet(reader: BinaryReader):
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
                reader = BinaryReader(data_view)

                ethernet_frame = read_ethernet_frame(reader)
                print(ethernet_frame)

                if ethernet_frame.ether_type == EtherType.IPv4:
                    ipv4_packet = read_ipv4_packet(reader)
                    print(ipv4_packet)

                    if ipv4_packet.protocol == SocketProtocols.TCP:
                        tcp_packet = read_tcp_packet(reader)
                        print(tcp_packet)
                    elif ipv4_packet.protocol == SocketProtocols.UDP:
                        udp_packet = read_udp_packet(reader)
                        print(udp_packet)
                    elif ipv4_packet.protocol == SocketProtocols.ICMP:
                        icmp_packet = read_icmp_packet(reader)
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
