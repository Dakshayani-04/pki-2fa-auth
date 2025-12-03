#!/usr/bin/env python3
import os
import sys
from datetime import datetime
import base64
import pyotp

SEED_FILE = "/data/seed.txt"
CRON_OUTPUT_FILE = "/cron/last_code.txt"

def hex_to_base32(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode('utf-8')

def generate_totp_code(hex_seed: str) -> str:
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed)
    return totp.now()

try:
    if not os.path.exists(SEED_FILE):
        sys.exit(0)
    with open(SEED_FILE, 'r') as f:
        hex_seed = f.read().strip()
    code = generate_totp_code(hex_seed)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    output_line = f"{timestamp} - 2FA Code: {code}\n"
    with open(CRON_OUTPUT_FILE, 'a') as f:
        f.write(output_line)
except Exception as e:
    print(f"Cron error: {str(e)}", file=sys.stderr)
    sys.exit(1)
