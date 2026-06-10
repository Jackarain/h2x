#!/usr/bin/env python3
"""
Generate seed corpus files for h2x fuzz targets.

Produces a set of minimal valid HTTP/2 frames + HPACK inputs
to help the fuzzer discover interesting paths from the start.
"""

import os
import struct

CORPORA_DIR = os.path.join(os.path.dirname(__file__), "corpora")
FRAMES_DIR = os.path.join(CORPORA_DIR, "fuzz_frames")
HPACK_DIR = os.path.join(CORPORA_DIR, "fuzz_hpack")


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def write_bin(path, data):
    with open(path, "wb") as f:
        f.write(data)


# -------------------------------------------------------------------
#  HTTP/2 frame helpers
# -------------------------------------------------------------------

def frame_header(ftype, flags, stream_id, payload_length):
    """9-byte HTTP/2 frame header."""
    return struct.pack("!IBBB", payload_length, ftype, flags, stream_id)


def settings_frame(entries, ack=False):
    """Build a complete SETTINGS frame."""
    payload = b""
    for ident, val in entries:
        payload += struct.pack("!HI", ident, val)
    hdr = frame_header(0x4, 0x01 if ack else 0x00, 0, len(payload))
    return hdr + payload


def headers_frame(stream_id, flags, fragment=b""):
    """Build a HEADERS frame."""
    hdr = frame_header(0x1, flags, stream_id, len(fragment))
    return hdr + fragment


def data_frame(stream_id, data, end_stream=False):
    """Build a DATA frame."""
    flags = 0x01 if end_stream else 0x00
    hdr = frame_header(0x0, flags, stream_id, len(data))
    return hdr + data


def goaway_frame(last_id, error_code, debug=b""):
    """Build a GOAWAY frame."""
    payload = struct.pack("!II", last_id & 0x7FFFFFFF, error_code) + debug
    hdr = frame_header(0x7, 0x00, 0, len(payload))
    return hdr + payload


def window_update_frame(stream_id, increment):
    """Build a WINDOW_UPDATE frame."""
    payload = struct.pack("!I", increment & 0x7FFFFFFF)
    hdr = frame_header(0x8, 0x00, stream_id, len(payload))
    return hdr + payload


def ping_frame(opaque_data, ack=False):
    """Build a PING frame."""
    flags = 0x01 if ack else 0x00
    hdr = frame_header(0x6, flags, 0, len(opaque_data))
    return hdr + opaque_data


def rst_stream_frame(stream_id, error_code):
    """Build a RST_STREAM frame."""
    payload = struct.pack("!I", error_code)
    hdr = frame_header(0x3, 0x00, stream_id, len(payload))
    return hdr + payload


def priority_frame(stream_id, exclusive, depends_on, weight):
    """Build a PRIORITY frame."""
    dep = (depends_on & 0x7FFFFFFF) | (0x80000000 if exclusive else 0)
    payload = struct.pack("!IB", dep, weight)
    hdr = frame_header(0x2, 0x00, stream_id, len(payload))
    return hdr + payload


def push_promise_frame(stream_id, promised_id, fragment=b"", padded=False):
    """Build a PUSH_PROMISE frame."""
    flags = 0x04  # END_HEADERS
    payload = struct.pack("!I", promised_id & 0x7FFFFFFF)
    payload += fragment
    hdr = frame_header(0x5, flags, stream_id, len(payload))
    return hdr + payload


# -------------------------------------------------------------------
#  HPACK helpers
# -------------------------------------------------------------------

def hpack_integer(value, nbit):
    """Encode a HPACK prefix integer."""
    mask = (1 << nbit) - 1
    if value < mask:
        return bytes([value])
    result = bytes([mask])
    value -= mask
    while value >= 128:
        result += bytes([0x80 | (value & 0x7F)])
        value >>= 7
    result += bytes([value & 0x7F])
    return result


def hpack_string(data, use_huffman=False):
    """Encode a HPACK string literal."""
    if use_huffman:
        # Simple placeholder — in practice this would use the HPACK Huffman table.
        # For seed purposes, plain is fine; the fuzzer will discover Huffman.
        pass
    prefix = 0x80 if use_huffman else 0x00
    enc = hpack_integer(len(data), 7)
    enc = bytes([enc[0] | prefix]) + enc[1:] + data
    return enc


# -------------------------------------------------------------------
#  Generate frame seeds
# -------------------------------------------------------------------

def generate_frame_seeds():
    ensure_dir(FRAMES_DIR)

    # 1. Valid SETTINGS frame (initial handshake)
    write_bin(os.path.join(FRAMES_DIR, "settings_valid"),
              settings_frame([
                  (0x01, 4096),    # HEADER_TABLE_SIZE
                  (0x02, 0),        # ENABLE_PUSH
                  (0x03, 100),      # MAX_CONCURRENT_STREAMS
                  (0x04, 65535),    # INITIAL_WINDOW_SIZE
                  (0x05, 16384),    # MAX_FRAME_SIZE
              ]))

    # 2. SETTINGS ACK
    write_bin(os.path.join(FRAMES_DIR, "settings_ack"),
              settings_frame([], ack=True))

    # 3. Empty SETTINGS
    write_bin(os.path.join(FRAMES_DIR, "settings_empty"),
              settings_frame([]))

    # 4. DATA frame with content
    write_bin(os.path.join(FRAMES_DIR, "data_small"),
              data_frame(1, b"Hello HTTP/2"))

    # 5. DATA frame END_STREAM
    write_bin(os.path.join(FRAMES_DIR, "data_end_stream"),
              data_frame(1, b"", end_stream=True))

    # 6. HEADERS frame (GET request minimal)
    # :method: GET  = static index 2
    # :path: /      = static index 4
    # :scheme: http = static index 6
    # Empty HPACK block is OK for seed; fuzzer will expand.
    write_bin(os.path.join(FRAMES_DIR, "headers_empty"),
              headers_frame(1, 0x05))  # END_HEADERS + END_STREAM

    # 7. PING frame
    write_bin(os.path.join(FRAMES_DIR, "ping"),
              ping_frame(b"\x00\x01\x02\x03\x04\x05\x06\x07"))

    # 8. PING ACK
    write_bin(os.path.join(FRAMES_DIR, "ping_ack"),
              ping_frame(b"\x00\x00\x00\x00\x00\x00\x00\x00", ack=True))

    # 9. GOAWAY frame
    write_bin(os.path.join(FRAMES_DIR, "goaway_clean"),
              goaway_frame(1, 0))  # H2_NO_ERROR, last_stream_id=1

    # 10. GOAWAY with debug data
    write_bin(os.path.join(FRAMES_DIR, "goaway_debug"),
              goaway_frame(0, 0x02, b"internal error"))

    # 11. WINDOW_UPDATE (connection-level)
    write_bin(os.path.join(FRAMES_DIR, "window_update_conn"),
              window_update_frame(0, 65535))

    # 12. WINDOW_UPDATE (stream-level)
    write_bin(os.path.join(FRAMES_DIR, "window_update_stream"),
              window_update_frame(1, 16384))

    # 13. RST_STREAM
    write_bin(os.path.join(FRAMES_DIR, "rst_cancel"),
              rst_stream_frame(1, 0x08))  # CANCEL

    # 14. RST_STREAM — PROTOCOL_ERROR
    write_bin(os.path.join(FRAMES_DIR, "rst_protocol"),
              rst_stream_frame(3, 0x01))

    # 15. PRIORITY frame
    write_bin(os.path.join(FRAMES_DIR, "priority"),
              priority_frame(1, False, 0, 16))

    # 16. PRIORITY exclusive
    write_bin(os.path.join(FRAMES_DIR, "priority_exclusive"),
              priority_frame(3, True, 1, 255))

    # 17. PUSH_PROMISE
    write_bin(os.path.join(FRAMES_DIR, "push_promise"),
              push_promise_frame(1, 2))

    # 18. CONTINUATION-like data (just a headers frame with END_HEADERS off)
    #    (we'll use TYPE=0x9 which is CONTINUATION)
    frag = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    hdr = frame_header(0x9, 0x00, 1, len(frag))
    write_bin(os.path.join(FRAMES_DIR, "continuation"), hdr + frag)

    # 19. HTTP/2 client connection preface (magic + SETTINGS)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    write_bin(os.path.join(FRAMES_DIR, "client_preface"),
              preface + settings_frame([(0x03, 100)]))

    # 20. All-zero frame (minimum valid frame header)
    write_bin(os.path.join(FRAMES_DIR, "zero_frame"), b"\x00" * 24)

    # 21. Frame with max payload size
    write_bin(os.path.join(FRAMES_DIR, "max_payload"),
              frame_header(0x0, 0x00, 1, 16384) + b"\x00" * 16384)

    # 22. Mixed valid sequences
    conn_preface = (preface +
                    settings_frame([(0x03, 100)]) +
                    settings_frame([], ack=True))
    write_bin(os.path.join(FRAMES_DIR, "handshake_sequence"), conn_preface)

    print(f"Generated {len(os.listdir(FRAMES_DIR))} frame seeds in {FRAMES_DIR}")


# -------------------------------------------------------------------
#  Generate HPACK seeds
# -------------------------------------------------------------------

def generate_hpack_seeds():
    ensure_dir(HPACK_DIR)

    # 1. Small inline integer (value < mask)
    write_bin(os.path.join(HPACK_DIR, "int_inline_5bit"),
              hpack_integer(10, 5))

    # 2. Overflow integer (value >= mask)
    write_bin(os.path.join(HPACK_DIR, "int_overflow_5bit"),
              hpack_integer(42, 5))

    # 3. Large multi-byte integer
    write_bin(os.path.join(HPACK_DIR, "int_large_7bit"),
              hpack_integer(1337, 7))

    # 4. Huge integer (many extension bytes)
    write_bin(os.path.join(HPACK_DIR, "int_huge_8bit"),
              hpack_integer(1000000, 8))

    # 5. Plain string (no Huffman)
    write_bin(os.path.join(HPACK_DIR, "string_plain"),
              hpack_string(b"content-type"))

    # 6. Empty string
    write_bin(os.path.join(HPACK_DIR, "string_empty"),
              hpack_string(b""))

    # 7. Long string
    write_bin(os.path.join(HPACK_DIR, "string_long"),
              hpack_string(b"abcdefghijklmnopqrstuvwxyz" * 4))

    # 8. Binary string
    write_bin(os.path.join(HPACK_DIR, "string_binary"),
              hpack_string(bytes(range(256))))

    # 9. HPACK indexed header field (static table index 1 = :authority)
    # First byte 0x80 | (1-1) = 0x80
    write_bin(os.path.join(HPACK_DIR, "indexed_1"),
              bytes([0x80]))

    # 10. HPACK indexed header field (index 15)
    write_bin(os.path.join(HPACK_DIR, "indexed_15"),
              hpack_integer(15, 7))

    # 11. HPACK literal with indexed name (name index 3 = :method)
    # Pattern: 01xxxxxx for literal with incremental indexing
    # index=3 : 01000010 | 0x02 (lower 6 bits = 3-1=2) → 0x42
    # Then value string
    write_bin(os.path.join(HPACK_DIR, "literal_name_indexed"),
              bytes([0x42 | 0x40]) + hpack_string(b"GET"))

    # 12. HPACK literal with new name+value
    write_bin(os.path.join(HPACK_DIR, "literal_new"),
              bytes([0x00]) + hpack_string(b"x-custom") + hpack_string(b"value42"))

    # 13. HPACK dynamic table size update
    write_bin(os.path.join(HPACK_DIR, "table_size_update"),
              hpack_integer(2048, 5))

    # 14. Huffman-coded string marker (prefix 0x80 + length)
    # Just the marker — may decode as invalid Huffman, that's OK for fuzzing.
    write_bin(os.path.join(HPACK_DIR, "huffman_prefix"),
              bytes([0x85, 0x00]))

    # 15. Index 62+ (dynamic table boundary)
    write_bin(os.path.join(HPACK_DIR, "index_dynamic_boundary"),
              hpack_integer(62, 7))

    # 16. Empty input (edge case)
    write_bin(os.path.join(HPACK_DIR, "empty"), b"")

    # 17. All-ones (trigger overflow protection)
    write_bin(os.path.join(HPACK_DIR, "all_ones"),
              bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))

    # 18. Truncated multi-byte (prefix mask set, no continuation)
    write_bin(os.path.join(HPACK_DIR, "truncated_5bit"),
              bytes([0x1F]))

    # 19. Truncated Huffman string (length says 10 but only 3 bytes follow)
    write_bin(os.path.join(HPACK_DIR, "truncated_huffman"),
              bytes([0x8A, 0x01, 0x02, 0x03, 0x04]))

    # 20. Zero-length Huffman string
    write_bin(os.path.join(HPACK_DIR, "huffman_zero_len"),
              bytes([0x80]))

    print(f"Generated {len(os.listdir(HPACK_DIR))} HPACK seeds in {HPACK_DIR}")


# -------------------------------------------------------------------
#  Main
# -------------------------------------------------------------------

def main():
    generate_frame_seeds()
    generate_hpack_seeds()


if __name__ == "__main__":
    main()