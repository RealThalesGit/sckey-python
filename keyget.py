#!/usr/bin/env python3
import sys
import math

def byte_array_to_hex(byte_array: bytes) -> str:
    return "".join(f"{b:02X}" for b in byte_array)


def hex_string_to_byte_array(hex_string: str) -> bytes:
    if len(hex_string) % 2 != 0:
        raise ValueError("Invalid hex string length")

    try:
        return bytes(
            int(hex_string[i:i + 2], 16)
            for i in range(0, len(hex_string), 2)
        )
    except ValueError:
        raise ValueError("Invalid hex char")


def read_unsigned_short_le(data: bytes, index: int) -> int:
    pos = 2 * index
    return data[pos] | (data[pos + 1] << 8)


def find_pattern(data: bytes, pattern: bytes, start_offset: int):
    if start_offset >= len(data):
        return None

    plen = len(pattern)
    for i in range(start_offset, len(data) - plen + 1):
        if data[i:i + plen] == pattern:
            return i
    return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    ent = 0.0
    length = len(data)

    for count in freq:
        if count > 0:
            p = count / length
            ent -= p * math.log2(p)

    return ent

def _rotate_left_16(value: int, shift: int) -> int:
    shift &= 15
    return ((value << shift) | (value >> (16 - shift))) & 0xFFFF


def load_server_public_key(server_public_key_obf: bytes) -> bytes:
    server_public_key = bytearray(32)

    for i in range(16):
        v16 = read_unsigned_short_le(server_public_key_obf, 31 - 2 * i + 32)
        v17_part1 = read_unsigned_short_le(server_public_key_obf, 2 * i + 1)
        v17_part2 = read_unsigned_short_le(server_public_key_obf, 2 * i)

        v17 = (v17_part1 ^ v16) | (v16 ^ v17_part2)

        shift = i & 7
        rotated = _rotate_left_16(v17, 11 - shift)

        final_value = rotated ^ read_unsigned_short_le(
            server_public_key_obf, 31 - i + 32
        )

        server_public_key[2 * i] = final_value & 0xFF
        server_public_key[2 * i + 1] = (final_value >> 8) & 0xFF

    return bytes(server_public_key)

PATTERN = bytes([0x1A, 0xD5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
KEY_SIZE = 128


class KeyInfo:
    def __init__(self, obfuscated: bytes, entropy: float):
        self.obfuscated = obfuscated
        self.entropy = entropy


def extract_key_from_library(path: str):
    with open(path, "rb") as f:
        data = f.read()

    potential_keys = _find_potential_keys(data)

    if not potential_keys:
        return None

    best = max(potential_keys, key=lambda k: k.entropy)
    return best.obfuscated


def _find_potential_keys(data: bytes):
    keys = []
    offset = 0

    while True:
        index = find_pattern(data, PATTERN, offset)
        if index is None:
            break

        key_start = index - KEY_SIZE
        if 0 <= key_start < len(data):
            obf = data[key_start:index]
            ent = entropy(obf)
            keys.append(KeyInfo(obf, ent))

        offset = index + len(PATTERN)
        if offset >= len(data):
            break

    return keys

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <libg.so|obfuscated_key>")
        return

    arg = sys.argv[1]
    try:
        obf = hex_string_to_byte_array(arg)

        if len(obf) != 128:
            print(f"Key must be 128 bytes, got {len(obf)}", file=sys.stderr)
            return

        key = load_server_public_key(obf)
        print(byte_array_to_hex(key))
        return

    except ValueError:
        pass
    try:
        obf = extract_key_from_library(arg)
        if obf is None:
            print(f"No keys in {arg}", file=sys.stderr)
            return

        key = load_server_public_key(obf)
        print(byte_array_to_hex(key))

    except Exception as e:
        print(f"Cannot read {arg}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()