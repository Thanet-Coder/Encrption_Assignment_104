"""
MAIN ENTRY POINT: Encryption_Assignment_104
-------------------------------------------
This is the user interface (UI) for the Secure Hybrid Backup System.
It coordinates the PKIManager, Vault, and EncryptionEngine.

SEQUENCE:
1. Create Directories (Infrastructure)
2. Initialize Backend Classes
3. Seed Default Users (Bootstrap)
4. Launch Interactive Menu
"""

import os
import sys
from pki_manager import PKIManager
from vault import Vault
from encryption import EncryptionEngine

def main_menu():
    # --- 1. FOLDER SHIELD (Infrastructure First) ---
    # We must create folders before generating any keys
    required_folders = ["keys", "vault", "backups", "exports"]
    for folder in required_folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"[SYSTEM] Created missing directory: /{folder}")

    # --- 2. INITIALIZE BACKEND ---
    pki = PKIManager()
    vault = Vault()
    engine = EncryptionEngine()

    # --- 3. BOOTSTRAP LOGIC (Seed Default Accounts) ---
    # This ensures User_A and User_B exist immediately for the demo
    default_users = {
        "User_A": "AlphaPassword123!",
        "User_B": "BravoPassword456!"
    }

    for username, password in default_users.items():
        # Check if the salt exists as proof the account is set up
        salt_path = os.path.join("vault", f"{username}.salt")
        if not os.path.exists(salt_path):
            print(f"[BOOTSTRAP] Setting up default account: {username}...")
            priv, pub = pki.generate_user_keys(username)
            vault.store_private_key(username, priv, password)
    # -----------------------------------------------

    current_user = None
    current_priv_key = None

    while True:
        print("\n" + "="*45)
        print("  SHIELD-PACK: SECURE HYBRID BACKUP SYSTEM  ")
        print("="*45)
        
        if not current_user:
            print("1. Login (User_A / User_B)")
            print("2. Register New User (e.g., Charlie)")
            print("3. Exit")
            
            choice = input("\nSelect an option: ")

            if choice == '1':
                username = input("Enter Username: ")
                password = input(f"Enter Password for {username}: ")
                
                # Attempt to unlock the vault
                key = vault.load_private_key(username, password)
                if key:
                    current_user = username
                    current_priv_key = key
                    print(f"\n[LOGIN] Welcome back, {username}!")
                
            elif choice == '2':
                new_user = input("Enter New Username: ")
                new_pass = input("Set Password: ")
                
                # Check if user already exists
                if os.path.exists(os.path.join("vault", f"{new_user}.salt")):
                    print(f"[ERROR] User {new_user} already exists.")
                    continue

                # Create keys and immediately lock them in the vault
                priv, pub = pki.generate_user_keys(new_user)
                vault.store_private_key(new_user, priv, new_pass)
                print(f"\n[SUCCESS] User {new_user} created and keys vaulted.")

            elif choice == '3':
                print("Exiting Secure System. Goodbye!")
                sys.exit()

        else:
            print(f"Logged in as: {current_user}")
            print("-" * 20)
            print("1. Encrypt & Backup a File")
            print("2. Decrypt & Restore a File")
            print("3. Logout")
            
            choice = input("\nSelect an option: ")

            if choice == '1':
                # Encryption Flow
                file_to_lock = input("Enter path of file to encrypt (e.g., test_message.txt): ")
                if not os.path.exists(file_to_lock):
                    print("[ERROR] File not found!")
                    continue
                
                recipient = input("Who is the recipient? (User_A/User_B): ")
                recip_pub = pki.load_public_key(recipient)
                
                if recip_pub:
                    engine.encrypt_file(file_to_lock, recip_pub, current_user)
                else:
                    print(f"[ERROR] Could not find Public Key for {recipient}.")

            elif choice == '2':
                # Decryption Flow
                try:
                    backups = [f for f in os.listdir("backups") if f.endswith(".enc")]
                    if not backups:
                        print("[INFO] No backup files found in /backups.")
                        continue

                    print("\nAvailable backups:")
                    for i, f in enumerate(backups):
                        print(f"{i+1}. {f}")
                    
                    file_choice = input("\nSelect file number to decrypt (or 'c' to cancel): ")
                    if file_choice.lower() == 'c': continue
                    
                    selected_file = backups[int(file_choice)-1]
                    full_path = os.path.join("backups", selected_file)
                    engine.decrypt_file(full_path, current_priv_key)
                except Exception as e:
                    print(f"[ERROR] Decryption failed: {e}")

            elif choice == '3':
                current_user = None
                current_priv_key = None
                print("\n[LOGOUT] Session ended.")

if __name__ == "__main__":
    main_menu()