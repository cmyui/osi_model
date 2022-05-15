#!/usr/bin/env python3.9
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from enum import IntFlag
from typing import Any
from typing import Mapping
from typing import Optional

# TODO: improve enum names
# TODO: replace wikipedia links with rfc links?

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


class BinaryReader:
    """\
    A class to read binary data from a buffer.

    >>>   reader = BinaryReader(b"\x01\x04\x00\x00\x00")
    >>>   assert reader.read_u8() == 0x01
    >>>   assert reader.read_u32() == 0x04
    """

    def __init__(self, data: bytes) -> None:
        self.data_view = memoryview(data)
        self.offset = 0

    def increment_offset(self, length: int) -> None:
        self.data_view = self.data_view[length:]
        self.offset += length

    def read_u8(self) -> int:
        val = self.data_view[0]
        self.increment_offset(1)
        return val

    def read_u16(self) -> int:
        (val,) = struct.unpack(">H", self.data_view[:2])
        self.increment_offset(2)
        return val

    def read_u32(self) -> int:
        (val,) = struct.unpack(">I", self.data_view[:4])
        self.increment_offset(4)
        return val

    def read_u64(self) -> int:
        (val,) = struct.unpack(">Q", self.data_view[:8])
        self.increment_offset(8)
        return val

    def read_bytes(self, length: int) -> bytes:
        val = self.data_view[:length].tobytes()
        self.increment_offset(length)
        return val


class EtherType(IntEnum):
    # https://en.wikipedia.org/wiki/EtherType#Values
    INTERNET_PROTOCOL_VERSION_4 = 0x0800
    ADDRESS_RESOLUTION_PROTOCOL = 0x0806
    INTERNET_PROTOCOL_VERSION_6 = 0x86DD


@dataclass
class BasePacket:
    data: Optional[BasePacket]


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
        data=None,  # to be assigned
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
    END_OF_OPTION_LIST = 0
    NO_OPERATION = 1
    # SECURITY = 2 (defunct)
    RECORD_ROUTE = 7
    ZSU = 10
    MTU_PROBE = 11
    MTU_REPLY = 12
    ENCODE = 15
    QUICK_START = 25
    # TODO: why are all experiement ids referencing RFC3692?? wikipedia bug?
    # EXPERIMENT = 30  # RFC3692-style
    TIME_STAMP = 68
    TRACE_ROUTE = 82
    # EXPERIMENT = 94  # RFC3692-style
    SECURITY = 130  # (RIPSO)
    LOOSE_SOURCE_ROUTE = 131
    EXTENDED_SECURITY = 133  # (RIPSO)
    COMMERCIAL_IP_SECURITY_OPTION = 134
    STREAM_ID = 136
    STRICT_SOURCE_ROUTE = 137
    VISA = 142
    IMI_TRAFFIC_DESCRIPTOR = 144
    EXTENDED_INTERNET_PROTOCOL = 145
    ADDRESS_EXTENSION = 147
    ROUTER_ALERT = 148
    SELECTIVE_DIRECTED_BROADCAST = 149
    DYNAMIC_PACKET_STATE = 151
    UPSTREAM_MULTICAST_PACKET = 152
    # EXPERIMENT = 158  # RFC3692-style
    EXPERIMENTAL_FLOW_CONTROL = 205
    # EXPERIMENT = 222  # RFC3692-style


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

    https://datatracker.ietf.org/doc/html/rfc791#section-3.1
    """
    reader_start_offset = reader.offset

    first_byte = reader.read_u8()
    assert ((first_byte & 0b11110000) >> 4) == 4
    header_length = first_byte & 0b00001111

    second_byte = reader.read_u8()
    # https://datatracker.ietf.org/doc/html/rfc2474
    differentiated_services_code_point = (second_byte & 0b11111100) >> 2
    # https://datatracker.ietf.org/doc/html/rfc3168
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

    options: list[IPv4Option] = []
    while ((reader.offset - reader_start_offset) / 4) < header_length:
        byte = reader.read_u8()
        option_copied = ((byte & 0b10000000) >> 7) == 1
        option_class = IPv4OptionClass((byte & 0b01100000) >> 5)
        option_type = IPv4OptionType(byte & 0b00011111)  # aka option_number
        option_length = reader.read_u8()
        # TODO: assert length is ok
        option_data = reader.read_bytes(option_length)

        options.append(
            IPv4Option(
                copied=option_copied,
                class_=option_class,
                type_=option_type,
                data=option_data,
            )
        )

        if option_type == IPv4OptionType.END_OF_OPTION_LIST:
            # break out of the loop early

            # TODO: skip padding bytes
            breakpoint()

            print(reader.data_view.tobytes())
            left = (header_length * 4) - (reader.offset - reader_start_offset)
            reader.increment_offset(left)

            break

    return IPv4Packet(
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
        data=None,  # to be assigned
    )


def read_arp_packet(reader: BinaryReader):
    ...


class TCPFlags(IntFlag):
    EXE_NONCE_CONCEALMENT_PROTECTION = 1 << 1
    CONGESTION_WINDOW_REDUCED = 1 << 2
    EXE_ECHO = 1 << 3
    URGENT = 1 << 4  # indicates the acknowledge field is significant
    ACKNOWLEDGEMENT = 1 << 5  # indicates the urgent pointer field is significant
    PUSH_FUNCTION = 1 << 6
    RESET_CONNECTION = 1 << 7
    SYNCHRONIZE = 1 << 8
    FIN = 1 << 9  # last packet from sender


class TCPOptionKind(IntEnum):
    # https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
    END_OF_OPTION_LIST = 0
    NO_OPERATION = 1
    MAXIMUM_SEGMENT_SIZE = 2
    WINDOW_SCALE = 3  # https://www.rfc-editor.org/rfc/rfc7323.html
    SELECTIVE_ACKNOWLEDGEMENT_PERMITTED = 4
    SELECTIVE_ACKNOWLEDGEMENT = 5
    ECHO = 6  # obseleted by option 8
    ECHO_REPLY = 7  # obseleted by option 8
    TIMESTAMPS = 8  # https://www.rfc-editor.org/rfc/rfc7323.html
    PARTIAL_ORDER_CONNECTION_PERMITTED = 9  # obselete
    PARTIAL_ORDER_SERVICE_PROFILE = 10  # obselete
    CC = 11  # obselete (TODO: name)
    CC_NEW = 12  # obselete (TODO: name)
    CC_ECHO = 13  # obselete (TODO: name)
    TCP_ALTERNATE_CHECKSUM_REQUEST = 14  # obselete
    TCP_ALTERNATE_CHECKSUM_DATA = 14  # obselete
    SKEETER_CONTROL = 15
    BUBBA_CONTROL = 16


@dataclass
class TCPOption:
    kind: int

    # only maximum segment size options have a body
    length: int
    data: Mapping[str, Any]


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
    """\
    Read a transmission control protocol packet.

    https://datatracker.ietf.org/doc/html/rfc793#section-3.1
    """

    reader_start_offset = reader.offset

    src_port = reader.read_u16()
    dest_port = reader.read_u16()
    sequence_number = reader.read_u32()
    acknowledgement_number = reader.read_u32()

    eleventh_byte = reader.read_u8()
    twelth_byte = reader.read_u8()
    data_offset = (eleventh_byte & 0b11110000) >> 4
    assert ((eleventh_byte & 0b00001110) >> 1) == 0  # reserved
    flags = TCPFlags(((eleventh_byte & 0b00000001) << 8) | twelth_byte)

    window_size = reader.read_u16()
    checksum = reader.read_u16()

    urgent_pointer = reader.read_u16()
    if not flags & TCPFlags.URGENT:
        # be a bit more explicit here
        urgent_pointer = None

    options = []
    while ((reader.offset - reader_start_offset) / 4) < data_offset:
        # b"\x02\x04\x05\xb4\x04\x02\x08\n7\xb6\x95\xb9\x00\x00\x00\x00\x01\x03\x03\x07"
        option_kind = TCPOptionKind(reader.read_u8())

        # TODO: make a decorator solution for these
        # TODO: make individual classes for options to parse data into explicitly?
        if option_kind == TCPOptionKind.END_OF_OPTION_LIST:
            # break out of the loop early

            # TODO: increment offset to skip padding bytes
            break
        elif option_kind == TCPOptionKind.NO_OPERATION:
            # no need to handle this
            continue
        elif option_kind == TCPOptionKind.MAXIMUM_SEGMENT_SIZE:
            option_length = reader.read_u8()
            assert option_length == 4
            option_data = {
                "maximum_segment_size": reader.read_u16(),
            }
        elif option_kind == TCPOptionKind.WINDOW_SCALE:
            # https://datatracker.ietf.org/doc/html/rfc7323#section-2.2
            option_length = reader.read_u8()
            assert option_length == 3
            option_data = {
                "shift": reader.read_u8(),
            }
        elif option_kind == TCPOptionKind.SELECTIVE_ACKNOWLEDGEMENT_PERMITTED:
            # https://datatracker.ietf.org/doc/html/rfc2018#section-2
            option_length = reader.read_u8()
            assert option_length == 2
            option_data = {}
        elif option_kind == TCPOptionKind.SELECTIVE_ACKNOWLEDGEMENT:
            # https://datatracker.ietf.org/doc/html/rfc2018#section-3
            option_length = reader.read_u8()

            # TODO: this packet - it's a bit more complex

            reader.increment_offset(option_length - 2)
            continue
        elif option_kind == TCPOptionKind.TIMESTAMPS:
            # https://datatracker.ietf.org/doc/html/rfc7323#section-3.2
            option_length = reader.read_u8()
            assert option_length == 10
            option_data = {
                "ts_val": reader.read_u32(),
                "ts_ecr": reader.read_u32(),
            }
        else:
            print("Unhandled option (assuming no data)", option_kind)

            # should these be None? 0 & None?
            option_length = 0
            option_data = {}

        options.append(
            TCPOption(
                kind=option_kind,
                length=option_length,
                data=option_data,
            )
        )

        if option_kind == TCPOptionKind.END_OF_OPTION_LIST:
            # break out of the loop early

            # TODO: i believe i need to skip padding bytes
            break

    return TCPPacket(
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
        data=None,  # to be assigned
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
        data=None,  # to be assigned
    )


@dataclass
class ICMPPacket(BasePacket):
    ...  # TODO


def read_icmp_packet(reader: BinaryReader) -> ICMPPacket:
    ...


def read_dns_packet(reader: BinaryReader):
    ...


def read_http_packet(reader: BinaryReader):
    ...


# def read_tls_packet(reader: BinaryReader):
#     ...


@dataclass
class NetworkStack:
    data_link: Optional[BasePacket] = None
    network: Optional[BasePacket] = None
    transport: Optional[BasePacket] = None
    application: Optional[BasePacket] = None


def read_full_network_stack(data: bytes) -> NetworkStack:
    """Parse the full network stack from data received from the client socket."""
    reader = BinaryReader(data)

    data_link = read_ethernet_frame(reader)
    network = transport = application = None

    if data_link.ether_type == EtherType.INTERNET_PROTOCOL_VERSION_4:
        network = read_ipv4_packet(reader)
        if network.protocol == SocketProtocols.TCP:
            transport = read_tcp_packet(reader)
        elif network.protocol == SocketProtocols.UDP:
            transport = read_udp_packet(reader)
        elif network.protocol == SocketProtocols.ICMP:
            transport = read_icmp_packet(reader)
        else:
            print(f"non-implemented ipv4 protocol: {network.protocol}")
    elif data_link.ether_type == EtherType.ADDRESS_RESOLUTION_PROTOCOL:
        transport = read_arp_packet(reader)
    else:
        print(f"non-implemented ethernet protocol: {data_link.ether_type}")

    return NetworkStack(data_link, network, transport, application)


def main() -> int:
    with socket.socket(
        family=socket.PF_PACKET,
        type=socket.SOCK_RAW,
        proto=socket.htons(ETH_P_ALL),  # accept all ethernet packets
    ) as sock:
        sock.bind(("eth0", 0))  # bind to network device

        total_bytes_read = 0

        while True:
            data = sock.recv(9000)
            if len(data) == 9000:
                # max size of a normal frame is 1500 bytes
                # max size of a jumbo frame is 9000 bytes
                breakpoint()

            network_stack = read_full_network_stack(data)
            total_bytes_read += len(data)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
