#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense

import os
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 100000
HASH_ALGORITHM = "sha256"


def encrypt(password, file_path):
    """Encrypt a file given a password. The password is expanded into bytes
    using PBKDF2 with SHA-256 and 100,000 iterations."""

    contents = open(file_path, "rb").read()
    iv = os.urandom(16)
    salt = os.urandom(30)
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM, password.encode("utf-8"), salt, ITERATIONS
    )
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(contents) + encryptor.finalize()
    return iv, salt, ct


def decrypt(password, file_path):
    """Decrypt a file given a password. The password is expanded into bytes
    using PBKDF2 with SHA-256 and 100,000 iterations. It's expected that the
    AES initialization vector is present as the first 16 bytes, with the salt
    being the following 30 bytes."""

    contents = open(file_path, "rb").read()
    iv = contents[:16]
    salt = contents[16:46]
    contents = contents[46:]
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM, password.encode("utf-8"), salt, ITERATIONS
    )
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    pt = decryptor.update(contents) + decryptor.finalize()
    return pt


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} Operation Password Input-File Output-File")
        print("Operation must be either encrypt or decrypt")
        sys.exit(1)

    operation = sys.argv[1]
    password = sys.argv[2]
    input_file_path = sys.argv[3]
    output_file_path = sys.argv[4]

    if not operation in ["encrypt", "decrypt"]:
        print("Operation must be either encrypt or decrypt")
        sys.exit(1)

    if operation == "encrypt":
        iv, salt, ct = encrypt(password, input_file_path)
        open(output_file_path, "wb").write(iv + salt + ct)
    elif operation == "decrypt":
        pt = decrypt(password, input_file_path)
        open(output_file_path, "wb").write(pt)
