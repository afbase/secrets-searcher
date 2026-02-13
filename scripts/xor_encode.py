#!/usr/bin/env python3
"""XOR encode/decode secrets for test fixtures. Key=0x5A, then base64.

Usage:
    python3 xor_encode.py encode "sk_live_abc123..."
    python3 xor_encode.py decode "base64string"
    echo "secret" | python3 xor_encode.py encode -   # read from stdin
"""
import sys, base64

XOR_KEY = 0x5A

def encode(s):
    return base64.b64encode(bytes(b ^ XOR_KEY for b in s.encode())).decode()

def decode(s):
    return bytes(b ^ XOR_KEY for b in base64.b64decode(s)).decode()

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "encode"
    val = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read().strip()
    print(encode(val) if cmd == "encode" else decode(val))
