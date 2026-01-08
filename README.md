# SHIELD-PACK: Secure Hybrid Backup System (Prototype)

## Project Overview
SHIELD-PACK is a high-security file encryption and backup prototype developed for [Your Course Name/Assignment Name]. The system implements a **Hybrid Cryptosystem** that combines the speed of Symmetric Encryption (AES) with the secure key distribution of Asymmetric Encryption (RSA).

This project focuses on the "Secure-by-Design" principle, ensuring that even if the physical storage is compromised, the data remains unreadable without the specific user's credentials and private key.

---

## 🔐 Core Security Architecture

### 1. Identity & PKI (pki_manager.py)
The system generates **RSA-4096** key pairs for every registered user. 
- **Public Keys:** Stored in the `/keys` directory. These are used by other users to encrypt data for a specific recipient.
- **Key Strength:** 4096-bit RSA was chosen to ensure the prototype is "Future-Proof" against increasing computational power and brute-force attacks.

### 2. The Vault & Argon2id (vault.py)
To protect the sensitive RSA Private Keys, this system implements a **Key Wrapping** strategy.
- **Argon2id:** Winner of the Password Hashing Competition. It is used to derive a 256-bit AES key from the user's password.
- **Parameterization:** The system uses a memory cost of 64MB and multiple lanes to resist GPU-based cracking attempts.
- **Storage:** Private keys are stored as encrypted blobs (`.enc`) in the `/vault` folder, alongside a unique random **Salt** for each user.

### 3. Hybrid Encryption Engine (encryption.py)
This module performs the actual data protection using a multi-step process:
1. **Session Key:** A unique, random AES-256 session key is generated for every file.
2. **Data Encryption:** The file is encrypted using **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and data integrity (authentication).
3. **Key Wrapping:** The AES session key is encrypted with the recipient's **RSA-4096 Public Key**.
4. **Packaging:** The final backup file contains the encrypted session key, the GCM nonce, and the ciphertext.

---

## 🛠 Project Structure
- `Encryption_Assignment_104.py`: The main entry point and user interface.
- `pki_manager.py`: Handles RSA key generation and public key distribution.
- `vault.py`: Manages the Argon2id key derivation and private key protection.
- `encryption.py`: Logic for hybrid file encryption and restoration.
- `/keys`: Publicly accessible RSA public keys.
- `/vault`: Encrypted private keys and their unique salts.
- `/backups`: Storage for encrypted data files.
- `/exports`: Destination for restored/decrypted files.

---

## 🚀 How to Run the Prototype

### Prerequisites
- Python 3.x
- `cryptography` library installed (`pip install cryptography`)

### Running the Demo
1. **Launch the Program:** Run `python Encryption_Assignment_104.py`.
2. **Register Users:** Use Option 2 to create `User_A` and `User_B`. This populates the keys and vault folders.
3. **Encryption:** Log in as `User_A`, choose a file (e.g., `test_message.txt`), and set the recipient as `User_B`.
4. **Decryption:** Log out, log in as `User_B`, and select the file from the "Restore" menu.
5. **Verification:** Check the `/exports` folder for the decrypted original file.

---

## ⚠️ Prototype Disclaimer
This software is an academic prototype. While it uses industry-standard algorithms, the following should be noted for production environments:
- **Local Storage:** In a production system, keys should be stored in a **Hardware Security Module (HSM)** or a dedicated **KMS** rather than local folders.
- **File Management:** For demonstration purposes, the `.gitignore` has been omitted to show the directory structure on GitHub; in production, keys and salts would never be committed to version control.
- **Error Handling:** Minimal error handling is implemented to keep the cryptographic logic clear for assessment.