#!/usr/bin/env python3
import os
import base64
import json
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pyotp
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = FastAPI()

SEED_FILE = "/data/seed.txt"
PRIVATE_KEY_FILE = "/app/student_private.pem"
DATA_DIR = Path("/data")

DATA_DIR.mkdir(parents=True, exist_ok=True)

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

class Verify2FARequest(BaseModel):
    code: str

def load_private_key():
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def decrypt_seed(encrypted_seed_b64: str) -> str:
    try:
        private_key = load_private_key()
        encrypted_seed = base64.b64decode(encrypted_seed_b64)
        decrypted_seed = private_key.decrypt(
            encrypted_seed,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hex_seed = decrypted_seed.decode('utf-8')
        if len(hex_seed) != 64 or not all(c in '0123456789abcdef' for c in hex_seed.lower()):
            raise ValueError("Invalid seed format")
        return hex_seed
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def hex_to_base32(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode('utf-8')

def generate_totp_code(hex_seed: str) -> str:
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed)
    return totp.now()

def get_remaining_validity() -> int:
    return 30 - (int(time.time()) % 30)

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed)
    return totp.verify(code, valid_window=valid_window)

@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(request: DecryptSeedRequest):
    try:
        hex_seed = decrypt_seed(request.encrypted_seed)
        with open(SEED_FILE, 'w') as f:
            f.write(hex_seed)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

@app.get("/generate-2fa")
async def generate_2fa_endpoint():
    try:
        if not os.path.exists(SEED_FILE):
            raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
        with open(SEED_FILE, 'r') as f:
            hex_seed = f.read().strip()
        code = generate_totp_code(hex_seed)
        valid_for = get_remaining_validity()
        return {"code": code, "valid_for": valid_for}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "Failed to generate 2FA code"})

@app.post("/verify-2fa")
async def verify_2fa_endpoint(request: Verify2FARequest):
    try:
        if not request.code:
            raise HTTPException(status_code=400, detail={"error": "Missing code"})
        if not os.path.exists(SEED_FILE):
            raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
        with open(SEED_FILE, 'r') as f:
            hex_seed = f.read().strip()
        is_valid = verify_totp_code(hex_seed, request.code, valid_window=1)
        return {"valid": is_valid}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "Failed to verify 2FA code"})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
