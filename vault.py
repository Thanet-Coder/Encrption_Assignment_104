"""
MODULE: Vault (Private Key Protection)
--------------------------------------
This module handles the secure storage of RSA Private Keys. It uses the 
Argon2id Key Derivation Function (KDF) to turn a user's password into 
a high-strength 256-bit AES encryption key.

PROTOTYPE DISCLAIMER:
In this prototype, salts are stored as local .salt files. In production, 
these would be stored in a secure database or handled by a Key Management 
Service (KMS) to prevent local file-system tampering.
"""

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Vault:
    def __init__(self):
        self.vault_path = "vault"

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Uses Argon2id to turn a password into a 32-byte AES key.
        """
        kdf = Argon2id(
            length=32,
            salt=salt,
            iterations=2,     
            memory_cost=65536, 
            lanes=4
        )
        return kdf.derive(password.encode())

    def store_private_key(self, username, private_key_obj, password):
        """
        1. Generates a unique Salt.
        2. Derives a key from the password.
        3. Encrypts the RSA Private Key using AES-GCM.
        4. Saves the encrypted blob and the salt.
        """
        # Create a 16-byte random salt
        salt = os.urandom(16)
        derived_key = self._derive_key(password, salt)

        # Convert the RSA Private Key object to bytes (unencrypted PEM)
        private_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encrypt with AES-GCM (Authenticated Encryption)
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12) # GCM needs a unique nonce
        encrypted_key = aesgcm.encrypt(nonce, private_bytes, None)

        # Save the salt and the encrypted key to the /vault folder
        with open(os.path.join(self.vault_path, f"{username}.salt"), "wb") as f:
            f.write(salt)
            
        with open(os.path.join(self.vault_path, f"{username}_priv.enc"), "wb") as f:
            # We store the nonce + the encrypted data together
            f.write(nonce + encrypted_key)

        print(f"[SUCCESS] Private key for {username} is now locked in the vault.")

    def load_private_key(self, username, password):
        """
        Unlocks the vault for a user.
        Reads the salt, re-derives the key, and decrypts the RSA Private Key.
        """
        try:
            with open(os.path.join(self.vault_path, f"{username}.salt"), "rb") as f:
                salt = f.read()
            
            with open(os.path.join(self.vault_path, f"{username}_priv.enc"), "rb") as f:
                data = f.read()
                nonce = data[:12]
                encrypted_blob = data[12:]

            # Re-derive the key using the same password and the stored salt
            derived_key = self._derive_key(password, salt)
            aesgcm = AESGCM(derived_key)
            
            # Decrypt the PEM bytes
            private_bytes = aesgcm.decrypt(nonce, encrypted_blob, None)
            
            # Reconstruct the RSA Private Key object
            return serialization.load_pem_private_key(private_bytes, password=None)

        except Exception as e:
            print(f"[ERROR] Authentication failed for {username}. Incorrect password or corrupt vault.")
            return None

