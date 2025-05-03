#!/usr/bin/env python3
import hashlib
import base64
import os
import sys

def create_qbittorrent_password_entry(password: str):
    # Generate a 16-byte random salt
    salt_bytes = os.urandom(16)
    num_iterations = 100000  # Iterations for key stretching
    hash_algo = 'sha512'  # Hashing algorithm

    # Compute the PBKDF2 hash
    derived_key = hashlib.pbkdf2_hmac(hash_algo, password.encode('utf-8'), salt_bytes, num_iterations)

    # Encode the salt and hash in Base64
    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
    hash_b64 = base64.b64encode(derived_key).decode('utf-8')

    # Construct the qBittorrent password entry line
    qbittorrent_password_entry = f'WebUI\\Password_PBKDF2=@ByteArray({salt_b64}:{hash_b64})'

    return qbittorrent_password_entry


print(create_qbittorrent_password_entry(sys.argv[1]))