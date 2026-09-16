"""
Auto-tune
=========

Startup self-test that measures which TLS ClientHello fragmentation
method gets past the local DPI, so NoDPI can pick a working one
automatically instead of relying on a fixed default.

`fragment_clienthello` is split out of ConnectionHandler so the proxy
and this self-test share a single implementation of the fragmentation
logic - if one changes, the other stays in sync automatically.
"""

import asyncio
import random
from typing import Dict, List, Optional, Tuple

# Small and deliberately short: each extra domain adds up to
# CONNECT_TIMEOUT + READ_TIMEOUT seconds per method if it's blocked.
TEST_DOMAINS: List[str] = ["youtube.com", "googlevideo.com", "ytimg.com"]

FRAGMENT_METHODS: List[str] = ["sni", "random"]

TLS_PORT = 443
CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 4.0


def _extract_sni_position(data: bytes) -> Optional[Tuple[int, int]]:
    """Identical to ConnectionHandler._extract_sni_position - kept as a
    free function here so it can be reused without instantiating a
    connection handler."""

    i = 0
    while i < len(data) - 8:
        if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
            ext_len = data[i + 3]
            server_name_list_len = data[i + 5]
            server_name_len = data[i + 8]
            if (
                ext_len - server_name_list_len == 2
                and server_name_list_len - server_name_len == 3
            ):
                sni_start = i + 9
                sni_end = sni_start + server_name_len
                return sni_start, sni_end
        i += 1
    return None


def fragment_clienthello(data: bytes, method: str) -> bytes:
    """Fragment a raw TLS ClientHello handshake payload.

    This is the same logic that used to live inline in
    ConnectionHandler._handle_initial_tls_data, extracted so both the
    live proxy path and the auto-tune self-test call one function.
    """

    parts: List[bytes] = []

    if method == "sni":
        sni_pos = _extract_sni_position(data)

        if sni_pos:
            part_start = data[: sni_pos[0]]
            sni_data = data[sni_pos[0]: sni_pos[1]]
            part_end = data[sni_pos[1]:]

            parts.append(
                bytes.fromhex("160304")
                + len(part_start).to_bytes(2, "big")
                + part_start
            )
            for i in range(0, len(sni_data), 2):
                chunk = sni_data[i: i + 2]
                parts.append(
                    bytes.fromhex("160304")
                    + len(chunk).to_bytes(2, "big")
                    + chunk
                )
            parts.append(
                bytes.fromhex("160304")
                + len(part_end).to_bytes(2, "big")
                + part_end
            )
        else:
            # No SNI found (shouldn't happen with our hand-built
            # ClientHello, but mirrors the real handler's behaviour of
            # sending nothing rather than guessing).
            pass

    elif method == "random":
        remaining = data
        host_end = remaining.find(b"\x00")
        if host_end != -1:
            parts.append(
                bytes.fromhex("160304")
                + (host_end + 1).to_bytes(2, "big")
                + remaining[: host_end + 1]
            )
            remaining = remaining[host_end + 1:]

        while remaining:
            chunk_len = random.randint(1, len(remaining))
            parts.append(
                bytes.fromhex("160304")
                + chunk_len.to_bytes(2, "big")
                + remaining[:chunk_len]
            )
            remaining = remaining[chunk_len:]
    else:
        raise ValueError(f"Unknown fragmentation method: {method}")

    return b"".join(parts)


def build_clienthello(domain: str) -> bytes:
    """Hand-build a minimal, valid TLS 1.2 ClientHello handshake body
    (the bytes that would follow the 5-byte record header) carrying an
    SNI extension for `domain`.

    A real browser ClientHello has more extensions, but this is enough
    to trigger the same SNI-based inspection that DPI performs, which
    is all the self-test needs to check.
    """

    host = domain.encode()

    client_random = bytes(random.getrandbits(8) for _ in range(32))
    session_id = b"\x00"
    cipher_suites = bytes.fromhex("002f0035")  # AES128-SHA, AES256-SHA
    compression = bytes.fromhex("0100")  # null compression

    server_name = bytes([0x00]) + len(host).to_bytes(2, "big") + host
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    sni_extension = (
        bytes.fromhex("0000")
        + len(server_name_list).to_bytes(2, "big")
        + server_name_list
    )

    extensions_len = len(sni_extension).to_bytes(2, "big")

    body = (
        bytes.fromhex("0303")  # client_version: TLS 1.2
        + client_random
        + session_id
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + compression
        + extensions_len
        + sni_extension
    )

    return bytes([0x01]) + len(body).to_bytes(3, "big") + body


async def _probe(domain: str, method: str) -> bool:
    """Send one fragmented ClientHello to `domain` and report whether a
    TLS handshake response (not a reset, alert, or timeout) came back."""

    fragments = fragment_clienthello(build_clienthello(domain), method)
    if not fragments:
        return False

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, TLS_PORT), timeout=CONNECT_TIMEOUT
        )
    except Exception:
        return False

    try:
        writer.write(fragments)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(5), timeout=READ_TIMEOUT)
    except Exception:
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    # response[0]: 0x16 = Handshake (ServerHello made it back, DPI let
    # it through), 0x15 = Alert (DPI or server rejected it), anything
    # else or an empty read means a reset/timeout already handled above.
    return len(response) > 0 and response[0] == 0x16


async def run_autotune(logger=None) -> Optional[str]:
    """Test every fragmentation method against a handful of commonly
    blocked domains and return the name of the best-performing one.

    Returns None if every method failed against every domain, so the
    caller can fall back to the configured default and warn the user
    rather than silently picking something that doesn't work.
    """

    scores: Dict[str, int] = {}

    for method in FRAGMENT_METHODS:
        if logger:
            logger.info(
                f"\033[92m[INFO]:\033[97m Auto-tune: testing '{method}' fragmentation..."
            )
        results = await asyncio.gather(
            *[_probe(domain, method) for domain in TEST_DOMAINS]
        )
        scores[method] = sum(1 for ok in results if ok)

    best_method = max(scores, key=scores.get)

    if logger:
        summary = ", ".join(
            f"{m}={s}/{len(TEST_DOMAINS)}" for m, s in scores.items()
        )
        logger.info(f"\033[92m[INFO]:\033[97m Auto-tune results: {summary}")

    if scores[best_method] == 0:
        return None

    return best_method
