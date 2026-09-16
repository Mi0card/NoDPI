"""
Evasion
=======

Extra DPI-evasion techniques layered on top of TLS ClientHello
fragmentation:

- Padding: grow the ClientHello with a standard RFC 7685 padding
  extension so it no longer fits in one small packet.
- Segmentation: send each TLS record as its own write()+drain() with
  Nagle's algorithm disabled, so records actually leave as separate
  TCP packets instead of being silently re-joined by a single
  b"".join() + one write() call.
- Fake packet: send a low-TTL decoy ClientHello (with an unrelated
  SNI) ahead of the real one, so it reaches an on-path DPI box but
  dies before reaching the real, further-away destination server.

None of this needs raw sockets or elevated privileges - everything
here is a standard setsockopt() call on the already-open outgoing TCP
socket, same as the rest of NoDPI.
"""

import random
import socket
from typing import List, Optional, Tuple


def set_tcp_nodelay(writer) -> None:
    """Disable Nagle's algorithm on the outgoing socket so that
    separate writer.write() calls actually leave as separate TCP
    segments instead of being coalesced by the kernel."""

    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


async def send_segmented(writer, parts: List[bytes]) -> None:
    """Send each TLS record as its own write()+drain() instead of
    joining everything into one buffer first. Combined with
    TCP_NODELAY, this makes each record leave as its own TCP packet -
    which is the actual point of "fragmentation"; concatenating the
    records back together before a single write() undoes most of it
    against DPI that matches on raw packet boundaries."""

    set_tcp_nodelay(writer)
    for part in parts:
        writer.write(part)
        await writer.drain()


def _find_extension(extensions: bytes, ext_type: int) -> Optional[Tuple[int, int]]:
    """Return (offset_of_length_field, payload_len) for the first
    extension of `ext_type` inside a ClientHello extensions block, or
    None if it isn't present."""

    pos = 0
    while pos + 4 <= len(extensions):
        cur_type = int.from_bytes(extensions[pos: pos + 2], "big")
        cur_len = int.from_bytes(extensions[pos + 2: pos + 4], "big")
        if cur_type == ext_type:
            return pos + 2, cur_len
        pos += 4 + cur_len
    return None


def _parse_clienthello_offsets(handshake: bytes) -> Optional[Tuple[int, int]]:
    """Locate the extensions_length field and the end of the
    extensions block inside a ClientHello handshake message.

    Returns (extensions_len_pos, extensions_end), or None if the
    message is too short or doesn't parse as expected - callers should
    leave the handshake untouched in that case rather than guess.
    """

    if len(handshake) < 4 or handshake[0] != 0x01:
        return None

    pos = 4 + 2 + 32  # handshake header + client_version + random
    if pos >= len(handshake):
        return None

    session_id_len = handshake[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(handshake):
        return None

    cipher_suites_len = int.from_bytes(handshake[pos: pos + 2], "big")
    pos += 2 + cipher_suites_len
    if pos >= len(handshake):
        return None

    compression_len = handshake[pos]
    pos += 1 + compression_len
    if pos + 2 > len(handshake):
        return None

    extensions_len_pos = pos
    extensions_len = int.from_bytes(handshake[pos: pos + 2], "big")
    extensions_end = pos + 2 + extensions_len
    if extensions_end > len(handshake):
        return None

    return extensions_len_pos, extensions_end


def pad_clienthello(handshake: bytes, target_size: int = 1400) -> bytes:
    """Pad a ClientHello handshake message up to `target_size` bytes
    using the standard RFC 7685 padding extension, so it no longer
    fits in a single small packet. Compliant TLS servers are required
    to ignore this extension, so it doesn't affect the handshake.

    If the ClientHello already carries a padding extension (common -
    Chrome and Firefox add one themselves), its payload is grown
    instead of adding a duplicate, since an extension type isn't
    supposed to repeat in one ClientHello.

    Returns the handshake unchanged if it's already >= target_size, or
    if it can't be safely parsed.
    """

    if len(handshake) >= target_size:
        return handshake

    offsets = _parse_clienthello_offsets(handshake)
    if offsets is None:
        return handshake

    extensions_len_pos, extensions_end = offsets
    extensions = handshake[extensions_len_pos + 2: extensions_end]

    existing = _find_extension(extensions, 0x0015)
    needed = target_size - len(handshake)

    if existing is not None:
        len_pos, cur_payload_len = existing
        payload_end = len_pos + 2 + cur_payload_len
        new_extensions = (
            extensions[:len_pos]
            + (cur_payload_len + needed).to_bytes(2, "big")
            + extensions[len_pos + 2: payload_end]
            + b"\x00" * needed
            + extensions[payload_end:]
        )
    else:
        if needed <= 4:
            return handshake
        padding_payload_len = needed - 4
        new_extension = (
            bytes.fromhex("0015")
            + padding_payload_len.to_bytes(2, "big")
            + b"\x00" * padding_payload_len
        )
        new_extensions = extensions + new_extension

    new_handshake = (
        handshake[:extensions_len_pos]
        + len(new_extensions).to_bytes(2, "big")
        + new_extensions
        + handshake[extensions_end:]
    )

    new_body_len = len(new_handshake) - 4
    return bytes([0x01]) + new_body_len.to_bytes(3, "big") + new_handshake[4:]


def _build_fake_clienthello_record(decoy_sni: bytes) -> bytes:
    """Build a complete, self-contained TLS record wrapping a minimal
    ClientHello carrying an unrelated SNI - just enough structure for
    a passive DPI to parse a (wrong) domain out of it."""

    client_random = bytes(random.getrandbits(8) for _ in range(32))
    session_id = b"\x00"
    cipher_suites = bytes.fromhex("002f0035")
    compression = bytes.fromhex("0100")

    server_name = bytes([0x00]) + len(decoy_sni).to_bytes(2, "big") + decoy_sni
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    sni_extension = (
        bytes.fromhex("0000")
        + len(server_name_list).to_bytes(2, "big")
        + server_name_list
    )
    extensions_len = len(sni_extension).to_bytes(2, "big")

    body = (
        bytes.fromhex("0303")
        + client_random
        + session_id
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + compression
        + extensions_len
        + sni_extension
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body

    return bytes.fromhex("160301") + len(handshake).to_bytes(2, "big") + handshake


async def send_fake_packet(writer, ttl: int = 8) -> None:
    """Send a decoy TLS record ahead of the real ClientHello, with the
    IP TTL lowered so it dies a few hops out - far enough to pass an
    on-path DPI box, not far enough to reach the real destination.

    The decoy carries a syntactically valid but unrelated SNI, so a
    DPI that inspects it without waiting for the real handshake reads
    the wrong domain, while the real server never receives this packet
    and is unaffected by it either way.
    """

    sock = writer.get_extra_info("socket")
    if sock is None:
        return

    fake = _build_fake_clienthello_record(b"www.example.com")

    is_ipv6 = sock.family == socket.AF_INET6
    opt_level = socket.IPPROTO_IPV6 if is_ipv6 else socket.IPPROTO_IP
    opt_name = socket.IPV6_UNICAST_HOPS if is_ipv6 else socket.IP_TTL

    try:
        original_ttl = sock.getsockopt(opt_level, opt_name)
    except OSError:
        return

    try:
        sock.setsockopt(opt_level, opt_name, ttl)
        writer.write(fake)
        await writer.drain()
    except OSError:
        pass
    finally:
        try:
            sock.setsockopt(opt_level, opt_name, original_ttl)
        except OSError:
            pass
