import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class PKIManager:
    """Handles RSA Key Generation, Storage, and Folder Management."""
    
    def __init__(self):
        # The core folders needed for the communal storage approach
        self.dirs = ['keys', 'vault', 'backups', 'exports']
        self._initialize_folders()

    def _initialize_folders(self):
        """Ensures the program has its 'working rooms' ready."""
        for folder in self.dirs:
            if not os.path.exists(folder):
                os.makedirs(folder)
                print(f"[SYSTEM] Created folder: {folder}")

    def generate_user_keys(self, username):
        """
        Creates a new RSA-4096 identity.
        Public keys are stored in /keys for everyone to see.
        Private keys are returned to be 'locked' by the Vault.
        """
        print(f"[PROCESS] Generating secure 4096-bit keys for {username}...")
        
        # Generate the private key (The 'Master Key')
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Derive the public key (The 'Padlock')
        public_key = private_key.public_key()

        # Save Public Key as a .pem file (Communal access)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        pub_path = os.path.join('keys', f"{username}_pub.pem")
        with open(pub_path, 'wb') as f:
            f.write(public_pem)
            
        print(f"[SUCCESS] {username}'s Public Key is now available in /keys.")
        
        # Return the objects so the next module can use them
        return private_key, public_key

    def load_public_key(self, username):
        """Fetches a recipient's public key from the communal folder."""
        path = os.path.join('keys', f"{username}_pub.pem")
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read())

# --- Startup Script ---
if __name__ == "__main__":
    # This initializes the 'Default Users' you requested
    pki = PKIManager()
    pki.generate_user_keys("User_A")
    pki.generate_user_keys("User_B")
    print("\n[FINISH] System Initialized. Check your project folders!")

    """
MODULE: PKI Manager (Public Key Infrastructure)
----------------------------------------------
This module serves as the identity foundation for the Secure Backup System.
It implements Asymmetric Cryptography using the RSA algorithm.

CORE RESPONSIBILITIES:
1. ENVIRONMENT SETUP: Automatically initializes the directory structure
   (keys, vault, backups, exports) to ensure system integrity.
   
2. IDENTITY GENERATION: Creates 4096-bit RSA key pairs. We use 4096-bit 
   rather than 2048-bit to ensure the system is "Future-Proof" against 
   increased computational power.

3. KEY SERIALIZATION: Converts complex mathematical key objects into 
   standardized PEM (Privacy-Enhanced Mail) format. 
   - Public Keys: Stored in /keys/ (Communal access for encryption).
   - Private Keys: Handled as objects to be passed to the Vault for 
     encryption (Argon2id + AES) before disk storage.

4. MULTI-USER SUPPORT: Dynamically names and retrieves keys based on 
   usernames, facilitating secure communication between User A, User B, 
   and any future users (like 'Charlie').

SECURITY NOTE: This module handles 'Plaintext' Private Keys in memory.
It must always be used in conjunction with the Vault module to ensure
that Private Keys are never stored unencrypted on the physical hard drive.
"""
"""
PROTOTYPE DISCLAIMER & LIMITATIONS:
----------------------------------
This application is developed as a functional prototype for academic assessment. 
In a production-level deployment, the following changes would be implemented:

1. KEY STORAGE: Public and private keys would not be stored in the local project 
   directory. Instead, they would be managed via a Hardware Security Module (HSM) 
   or a dedicated Key Management Service (KMS) like AWS KMS or HashiCorp Vault.

2. REPOSITORY SECURITY: Sensitive directories (/keys and /vault) would be 
   strictly excluded from version control via .gitignore to prevent accidental 
   exposure of cryptographic material.

3. USER AUTHENTICATION: The system would use a centralized identity provider 
   (OIDC/SAML) rather than local password-based key derivation.

4. LOGGING: Production systems would implement immutable audit logs for every 
   encryption/decryption event to ensure non-repudiation.
"""