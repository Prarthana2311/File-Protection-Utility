import argparse
import getpass
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
SALT_SIZE = 16       # 128-bit random salt
NONCE_SIZE = 12      # 96-bit standard nonce for AES-GCM
ITERATIONS = 600000  # OWASP recommendation for PBKDF2-HMAC-SHA256
KEY_LENGTH = 32      # 256 bits for AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_path: str, output_path: str, password: str):
    """Encrypts a file with AES-256-GCM and prepends salt + nonce to the ciphertext."""
    if not os.path.exists(input_path):
        print(f"[!] Error: File '{input_path}' not found.")
        # In a script, sys.exit(1) is appropriate. In a notebook, it stops the kernel.
        # For demonstration, we'll return False or raise a specific error.
        return False

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Generate cryptographic randomness
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Key derivation & encryption
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # GCM includes a 16-byte MAC tag

    # File structure: [ Salt (16B) ] + [ Nonce (12B) ] + [ Ciphertext + Tag ]
    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"[+] Successfully encrypted: '{input_path}' -> '{output_path}'")
    return True


def decrypt_file(input_path: str, output_path: str, password: str):
    """Decrypts an encrypted file and verifies MAC tag integrity."""
    if not os.path.exists(input_path):
        print(f"[!] Error: File '{input_path}' not found.")
        return False

    with open(input_path, "rb") as f:
        encrypted_data = f.read()

    header_len = SALT_SIZE + NONCE_SIZE
    if len(encrypted_data) < header_len + 16:  # 16 bytes minimum for AES-GCM tag
        print("[!] Error: File is corrupted or not a valid encrypted file.")
        return False

    # Unpack header
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:header_len]
    ciphertext = encrypted_data[header_len:]

    # Key derivation & decryption
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print("[!] Decryption failed: Invalid password or corrupted/tampered file (MAC check failed).")
        return False

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Successfully decrypted: '{input_path}' -> '{output_path}'")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="AES-256-GCM File Encryption & Decryption Utility")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Action to execute")
    parser.add_argument("file", help="Target input file")
    parser.add_argument("-o", "--output", help="Optional output path")

    args = parser.parse_args(argv) # Pass argv to parse_args()

    if args.mode == "encrypt":
        output_file = args.output or f"{args.file}.enc"
        pwd = getpass.getpass("Enter encryption password: ")
        pwd_confirm = getpass.getpass("Confirm password: ")
        if pwd != pwd_confirm:
            print("[!] Error: Passwords do not match.")
            return # Changed sys.exit(1) to return
        encrypt_file(args.file, output_file, pwd)

    elif args.mode == "decrypt":
        default_out = args.file[:-4] if args.file.endswith(".enc") else f"{args.file}.dec"
        output_file = args.output or default_out
        pwd = getpass.getpass("Enter decryption password: ")
        decrypt_file(args.file, output_file, pwd)


if __name__ == "__main__":
    # Example usage for notebook environment
    # Create a dummy file for testing
    with open("test_file.txt", "w") as f:
        f.write("This is a secret message.")

    print("\n--- Encrypting example ---")
    main(argv=["encrypt", "test_file.txt"])

    print("\n--- Decrypting example ---")
    main(argv=["decrypt", "test_file.txt.enc"])

    print("\n--- Cleaning up test files ---")
    if os.path.exists("test_file.txt"):
        os.remove("test_file.txt")
    if os.path.exists("test_file.txt.enc"):
        os.remove("test_file.txt.enc")
    if os.path.exists("test_file.txt.dec"):
        os.remove("test_file.txt.dec")