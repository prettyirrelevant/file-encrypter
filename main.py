#!/usr/bin/env python3
import argparse
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__version__ = '0.0.1'

def generate_fernet_key_from_password(password: str) -> bytes:
    """This function generates a Fernet key from a random string.

    Uses Scrypt for the Key Derivation Function(KDF).
    To learn more, https://words.filippo.io/the-scrypt-parameters/
    """
    encoded_password = password.encode()
    kdf = Scrypt(
        salt=encoded_password,
        length=32,
        p=1,
        r=8,
        n=1048576,  # must be a power of 2.
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(encoded_password))


def encrypt_file(file_to_encrypt: Path, password: str) -> None:
    """Encrypts a file using a password with Fernet.

    This is suitable for text files only.
    """
    encrypted_content = []

    cipher = generate_fernet_key_from_password(password)
    fernet = Fernet(cipher)

    encrypted_file_path = file_to_encrypt.parent / f'{file_to_encrypt.name}.encrypted'
    encrypted_file_path.resolve()
    with open(file_to_encrypt, 'rb') as f:
        for line in f.readlines():
            encrypted_content.append(fernet.encrypt(line))

    with open(encrypted_file_path, 'wb') as f:
        for entry in encrypted_content:
            f.write(entry + b'\n')


def decrypt_file(file_to_decrypt: Path, password: str) -> None:
    """Decrypts a file that was previously encrypted using the password."""
    decrypted_content = []

    cipher = generate_fernet_key_from_password(password)
    fernet = Fernet(cipher)

    decrypted_filename = file_to_decrypt.name.split('.encrypted')[0]
    decrypted_file_path = file_to_decrypt.parent / f'{decrypted_filename}.decrypted'
    decrypted_file_path.resolve()
    with open(file_to_decrypt, 'rb') as f:
        for line in f:
            decrypted_content.append(fernet.decrypt(line))

    with open(decrypted_file_path, 'wb') as f:
        for entry in decrypted_content:
            f.write(entry)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='File Encrypter',
        description='Encrypt and decrypt text files easily using a password.',
    )
    parser.add_argument(
        '-f',
        '--filename',
        required=True,
        type=lambda v: Path(v).resolve(),
        help='path to the file to encrypt/decrypt',
    )
    parser.add_argument(
        '-p',
        '--password',
        required=True,
        type=lambda v: str(v),
        help='used to encrypt/decrypt the file'
    )
    parser.add_argument(
        '-a',
        '--action',
        choices=['encrypt', 'decrypt'],
        help='operation to be performed on the file given',
        required=True,
    )
    args = parser.parse_args()
    if args.action == 'encrypt':
        encrypt_file(args.filename, args.password)
    else:
        decrypt_file(args.filename, args.password)
