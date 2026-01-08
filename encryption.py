"""
MODULE: Encryption Engine (Hybrid Cryptosystem)
----------------------------------------------
This module performs Hybrid Encryption:
1. Symmetric: AES-256-GCM encrypts the actual file data.
2. Asymmetric: RSA-4096 encrypts the AES session key.

PROTOTYPE DISCLAIMER:
In this prototype, the encrypted 'Session Key' is prepended to the data file.
In a production system, we would use a standardized envelope format like 
CMS (Cryptographic Message Syntax) or OpenPGP.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptionEngine:
    def __init__(self):
        self.backup_path = "backups"
        self.export_path = "exports"

    def encrypt_file(self, source_file, recipient_pub_key, sender_username):
        """
        Encrypts a file so ONLY the owner of the public key can open it.
        """
        # 1. Generate a one-time 'Session Key' (AES-256)
        session_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)

        # 2. Read the original file data
        with open(source_file, 'rb') as f:
            data = f.read()

        # 3. Encrypt the data with AES
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # 4. Encrypt the AES 'Session Key' with the Recipient's RSA Public Key
        encrypted_session_key = recipient_pub_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 5. Save the 'Encrypted Package' to the communal backups folder
        # Structure: [Length of RSA Key (4 bytes)] + [RSA Encrypted Key] + [Nonce] + [Ciphertext]
        file_name = os.path.basename(source_file)
        dest_path = os.path.join(self.backup_path, f"{file_name}.enc")
        
        with open(dest_path, 'wb') as f:
            # We store the length of the RSA block so the decrypter knows where it ends
            f.write(len(encrypted_session_key).to_bytes(4, byteorder='big'))
            f.write(encrypted_session_key)
            f.write(nonce)
            f.write(ciphertext)

        print(f"[SUCCESS] File '{file_name}' encrypted for the recipient.")

    def decrypt_file(self, encrypted_file_path, recipient_priv_key):
        """
        Uses the recipient's private key to unlock the AES key and decrypt the file.
        """
        with open(encrypted_file_path, 'rb') as f:
            # Read how big the RSA encrypted block is
            key_length = int.from_bytes(f.read(4), byteorder='big')
            encrypted_session_key = f.read(key_length)
            nonce = f.read(12)
            ciphertext = f.read()

        # 1. Decrypt the AES Session Key using RSA Private Key
        session_key = recipient_priv_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Decrypt the actual data using the recovered AES Session Key
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # 3. Save to the persistent 'exports' folder
        original_name = os.path.basename(encrypted_file_path).replace(".enc", "")
        output_path = os.path.join(self.export_path, f"RESTORED_{original_name}")
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"[SUCCESS] Decryption complete. File saved to: {output_path}")
