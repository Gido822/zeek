#!/usr/bin/env python3

"""
Generate a deterministic TLS 1.2 trace where the TCP responder acts as
the TLS client and sends the ClientHello, while the TCP originator acts
as the TLS server.

This trace is intended to exercise TLS DPD when the TLS application
roles are reversed relative to the TCP originator/responder roles.

AI usage:
The initial version of this script was generated with ChatGPT using
OpenAI GPT-5.6
"""

import hashlib
import ipaddress
import struct
from pathlib import Path


ORIG_MAC = bytes.fromhex("020000000010")
RESP_MAC = bytes.fromhex("020000000020")

ORIG_IP = "192.0.2.10"
RESP_IP = "192.0.2.20"

ORIG_PORT = 41000
RESP_PORT = 31338

ORIG_ISN = 1000
RESP_ISN = 5000

OUTPUT = Path("tls-1.2-clienthello-from-tcp-responder.pcap")

# Fixed packet timestamps: 1.000000, 1.001000, ...
BASE_TS_SEC = 1
BASE_TS_USEC = 0
TS_STEP_USEC = 1000


# ---------------------------------------------------------------------------
# Checksums / packet builders
# ---------------------------------------------------------------------------


def checksum(data: bytes) -> int:
    """Return the standard Internet checksum."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac_frame(src: bytes, dst: bytes, payload: bytes) -> bytes:
    # Ethernet II, EtherType IPv4.
    return dst + src + b"\x08\x00" + payload


def ipv4_packet(src: str, dst: str, payload: bytes) -> bytes:
    src_b = ipaddress.IPv4Address(src).packed
    dst_b = ipaddress.IPv4Address(dst).packed

    version_ihl = 0x45
    tos = 0
    total_length = 20 + len(payload)
    identification = 0
    flags_fragment = 0
    ttl = 64
    protocol = 6  # TCP
    header_checksum = 0

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src_b,
        dst_b,
    )

    header_checksum = checksum(header)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src_b,
        dst_b,
    )

    return header + payload


def tcp_flags(value: str) -> int:
    flags = 0
    mapping = {
        "F": 0x01,
        "S": 0x02,
        "R": 0x04,
        "P": 0x08,
        "A": 0x10,
        "U": 0x20,
        "E": 0x40,
        "C": 0x80,
    }

    for flag in value:
        flags |= mapping[flag]

    return flags


def tcp_segment(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes = b"",
) -> bytes:
    src_b = ipaddress.IPv4Address(src_ip).packed
    dst_b = ipaddress.IPv4Address(dst_ip).packed

    data_offset = 5  # 20-byte TCP header, no options
    offset_reserved = data_offset << 4
    window = 8192
    urgptr = 0

    header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        offset_reserved,
        tcp_flags(flags),
        window,
        0,  # checksum filled below
        urgptr,
    )

    tcp_length = len(header) + len(payload)
    pseudo_header = src_b + dst_b + struct.pack("!BBH", 0, 6, tcp_length)
    tcp_checksum = checksum(pseudo_header + header + payload)

    header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        offset_reserved,
        tcp_flags(flags),
        window,
        tcp_checksum,
        urgptr,
    )

    return header + payload


def packet(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes = b"",
) -> bytes:
    tcp = tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
    ip = ipv4_packet(src_ip, dst_ip, tcp)
    return mac_frame(src_mac, dst_mac, ip)


# ---------------------------------------------------------------------------
# Deterministic TLS 1.2 messages
# ---------------------------------------------------------------------------


def tls_record(content_type: int, version: bytes, payload: bytes) -> bytes:
    return bytes([content_type]) + version + struct.pack("!H", len(payload)) + payload


def tls_handshake(handshake_type: int, body: bytes) -> bytes:
    return bytes([handshake_type]) + len(body).to_bytes(3, "big") + body


def make_client_hello() -> bytes:
    # Everything is fixed intentionally. The goal is a deterministic Zeek DPD
    # fixture, not a cryptographically complete TLS session.
    client_random = bytes(range(0x00, 0x20))

    body = b"".join(
        [
            b"\x03\x03",          # TLS 1.2
            client_random,          # fixed Random
            b"\x00",              # empty session ID
            b"\x00\x02",          # cipher_suites length
            b"\x00\x2f",          # TLS_RSA_WITH_AES_128_CBC_SHA
            b"\x01",              # compression_methods length
            b"\x00",              # null compression
            b"\x00\x00",          # extensions length
        ]
    )

    return tls_record(
        0x16,                       # Handshake
        b"\x03\x01",              # TLS record version
        tls_handshake(0x01, body),  # ClientHello
    )


def make_server_hello() -> bytes:
    server_random = bytes(range(0x20, 0x40))

    body = b"".join(
        [
            b"\x03\x03",          # TLS 1.2
            server_random,          # fixed Random
            b"\x00",              # empty session ID
            b"\x00\x2f",          # TLS_RSA_WITH_AES_128_CBC_SHA
            b"\x00",              # null compression
            b"\x00\x00",          # extensions length
        ]
    )

    return tls_record(
        0x16,
        b"\x03\x03",
        tls_handshake(0x02, body),  # ServerHello
    )


# ---------------------------------------------------------------------------
# PCAP generation
# ---------------------------------------------------------------------------


def build_frames() -> list[bytes]:
    frames = []
    orig_seq = ORIG_ISN
    resp_seq = RESP_ISN

    def add_orig(flags: str, payload: bytes = b"") -> None:
        frames.append(
            packet(
                ORIG_MAC,
                RESP_MAC,
                ORIG_IP,
                RESP_IP,
                ORIG_PORT,
                RESP_PORT,
                orig_seq,
                resp_seq if "A" in flags else 0,
                flags,
                payload,
            )
        )

    def add_resp(flags: str, payload: bytes = b"") -> None:
        frames.append(
            packet(
                RESP_MAC,
                ORIG_MAC,
                RESP_IP,
                ORIG_IP,
                RESP_PORT,
                ORIG_PORT,
                resp_seq,
                orig_seq if "A" in flags else 0,
                flags,
                payload,
            )
        )

    # Normal TCP three-way handshake.
    add_orig("S")
    orig_seq += 1

    add_resp("SA")
    resp_seq += 1

    add_orig("A")

    # Reverse application roles:
    #   TCP responder  = TLS client
    #   TCP originator = TLS server
    client_hello = make_client_hello()
    server_hello = make_server_hello()

    add_resp("PA", client_hello)
    resp_seq += len(client_hello)

    add_orig("A")

    add_orig("PA", server_hello)
    orig_seq += len(server_hello)

    add_resp("A")

    # Clean deterministic shutdown.
    add_resp("FA")
    resp_seq += 1

    add_orig("FA")
    orig_seq += 1

    add_resp("A")

    return frames


def write_pcap(path: Path, frames: list[bytes]) -> None:
    # Classic PCAP, little-endian, microsecond timestamps, Ethernet link type.
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,  # LINKTYPE_ETHERNET
    )

    with path.open("wb") as f:
        f.write(global_header)

        timestamp_us = BASE_TS_USEC
        timestamp_sec = BASE_TS_SEC

        for frame in frames:
            sec = timestamp_sec + timestamp_us // 1_000_000
            usec = timestamp_us % 1_000_000

            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)

            timestamp_us += TS_STEP_USEC


def main() -> None:
    client_hello = make_client_hello()
    server_hello = make_server_hello()

    # Sanity checks relevant to Zeek's TLS DPD signatures.
    assert client_hello.startswith(b"\x16\x03\x01")
    assert client_hello[5] == 0x01  # ClientHello
    assert server_hello.startswith(b"\x16\x03\x03")
    assert server_hello[5] == 0x02  # ServerHello

    write_pcap(OUTPUT, build_frames())

    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()

    print(f"Wrote: {OUTPUT}")
    print(f"SHA256: {digest}")
    print(f"TCP originator: {ORIG_IP}:{ORIG_PORT} (TLS server)")
    print(f"TCP responder : {RESP_IP}:{RESP_PORT} (TLS client)")


if __name__ == "__main__":
    main()
