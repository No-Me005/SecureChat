#!/usr/bin/env python3
"""
Cryptographic Engine Module
Handles Hybrid Encryption (AES + RSA) and Forward Secrecy for the Secure Chat Tool.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """
    Manages hybrid encryption, decryption, and ephemeral key generation 
    to ensure forward secrecy.
    """
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_ephemeral_keypair(self):
        """
        Generate a temporary (ephemeral) RSA key pair for a single session.
        This ensures Forward Secrecy: if a long-term key is compromised later, 
        past session keys cannot be decrypted.
        """
        print("[*] Generating ephemeral session key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_message(self, message: bytes, recipient_public_key):
        """
        Hybrid Encryption:
        1. Generate a random AES-256 key.
        2. Encrypt the message with AES-256-GCM.
        3. Encrypt the AES key with the recipient's RSA public key.
        """
        print("[*] Encrypting message using Hybrid Encryption...")
        
        # 1. Generate random AES-256 key (32 bytes)
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        
        # 2. Encrypt the actual message
        nonce = os.urandom(12) # 12-byte nonce for AES-GCM
        encrypted_message = aesgcm.encrypt(nonce, message, None)
        
        # 3. Encrypt the AES key using recipient's RSA public key
        encrypted_aes_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("[+] Message encrypted successfully.")
        # Return encrypted AES key, nonce, and encrypted message
        return encrypted_aes_key, nonce, encrypted_message

    def decrypt_message(self, encrypted_aes_key, nonce, encrypted_message, recipient_private_key):
        """
        Hybrid Decryption:
        1. Decrypt the AES key using the recipient's RSA private key.
        2. Decrypt the message using the AES key.
        """
        print("[*] Decrypting message using Hybrid Decryption...")
        
        # 1. Decrypt the AES key
        aes_key = recipient_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 2. Decrypt the message
        aesgcm = AESGCM(aes_key)
        decrypted_message = aesgcm.decrypt(nonce, encrypted_message, None)
        
        print("[+] Message decrypted successfully.")
        return decrypted_message


# Example usage and testing
if __name__ == "__main__":
    print("=== Cryptographic Engine Test ===\n")
    
    engine = CryptoEngine()
    
    # 1. Simulate Bob generating an ephemeral session key pair
    print("--- Bob's Side ---")
    bob_private_key, bob_public_key = engine.generate_ephemeral_keypair()
    
    # 2. Alice wants to send a secret message to Bob
    print("\n--- Alice's Side ---")
    secret_message = b"Hey Bob, let's meet at the secure location at 10 PM."
    
    # Alice encrypts the message using Bob's PUBLIC key
    enc_aes_key, nonce, enc_message = engine.encrypt_message(secret_message, bob_public_key)
    
    print(f"\nOriginal Message: {secret_message.decode()}")
    print(f"Encrypted Message (Hex): {enc_message.hex()[:50]}...")
    
    # 3. Bob receives the data and decrypts it using his PRIVATE key
    print("\n--- Bob's Side ---")
    decrypted_message = engine.decrypt_message(enc_aes_key, nonce, enc_message, bob_private_key)
    
    print(f"\nDecrypted Message: {decrypted_message.decode()}")
    
    # 4. Verify they match
    if secret_message == decrypted_message:
        print("\n[+] SUCCESS: Original and decrypted messages match perfectly!")
    else:
        print("\n[-] FAILURE: Messages do not match.")
        
