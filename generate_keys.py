#!/usr/bin/env python3
import os
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def save_keys(private_pem, public_pem):
    with open('student_private.pem', 'wb') as f:
        f.write(private_pem)
    print("‚úì Saved student_private.pem")
    with open('student_public.pem', 'wb') as f:
        f.write(public_pem)
    print("‚úì Saved student_public.pem")

def download_instructor_key():
    try:
        url = "https://partnr-public.s3.us-east-1.amazonaws.com/gpp-resources/instructor_public.pem"
        response = requests.get(url)
        response.raise_for_status()
        with open('instructor_public.pem', 'wb') as f:
            f.write(response.content)
        print("‚úì Downloaded instructor_public.pem")
    except Exception as e:
        print(f"‚úó Failed to download instructor public key: {e}")

def request_encrypted_seed(student_id, github_repo_url, public_pem):
    try:
        api_url = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
        public_key_str = public_pem.decode('utf-8')
        public_key_line = public_key_str.replace('\n', '\\n')
        payload = {
            "student_id": student_id,
            "github_repo_url": github_repo_url,
            "public_key": public_key_line
        }
        print(f"\nÌ≥§ Requesting encrypted seed from API...")
        print(f"   Student ID: {student_id}")
        print(f"   GitHub Repo: {github_repo_url}")
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            encrypted_seed = data.get("encrypted_seed")
            with open('encrypted_seed.txt', 'w') as f:
                f.write(encrypted_seed)
            print(f"‚úì Encrypted seed received and saved to encrypted_seed.txt")
            return encrypted_seed
        else:
            print(f"‚úó API Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"‚úó Failed to request encrypted seed: {e}")

def main():
    print("Ì¥ê PKI 2FA Microservice - Key Generation & Setup\n")
    
    print("Step 1: Generating RSA 4096-bit keypair...")
    private_pem, public_pem = generate_rsa_keypair()
    save_keys(private_pem, public_pem)
    
    print("\nStep 2: Downloading instructor's public key...")
    download_instructor_key()
    
    print("\nStep 3: Requesting encrypted seed from instructor API...")
    print("‚ö†Ô∏è  You need to provide:")
    student_id = input("   Enter your Student ID: ").strip()
    github_repo_url = input("   Enter GitHub Repo URL (https://github.com/Dakshayani-04/pki-2fa-auth): ").strip()
    
    if not student_id or not github_repo_url:
        print("‚úó Student ID and GitHub Repo URL are required!")
        return
    
    request_encrypted_seed(student_id, github_repo_url, public_pem)
    
    print("\n‚úÖ Setup complete!")
    print("Next steps:")
    print("  git add .")
    print("  git commit -m 'Add project files'")
    print("  git push origin main")

if __name__ == "__main__":
    main()
