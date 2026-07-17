#!/usr/bin/env python3
"""
Virtual HSM and Key Manager Module
Simulates a Hardware Security Module (HSM) to securely store and use private keys.
"""

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class VirtualHSM:
    """
    Simulates a Hardware Security Module.
    The private key is loaded into memory but never exposed directly.
    Only signing and decryption operations are allowed.
    """
    
    def __init__(self):
        self._private_key = None
        self._is_locked = True
        self.backend = default_backend()
    
    def load_key_from_pem(self, key_path, password=None):
        """Load a private key from a PEM file into the secure HSM memory."""
        print(f"[*] Loading private key into Virtual HSM from: {key_path}")
        
        with open(key_path, "rb") as f:
            # If the key is encrypted with a password, we would pass it here.
            # For our CA keys, we left them unencrypted for simplicity.
            self._private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=self.backend
            )
        
        self._is_locked = False
        print("[+] Private key securely loaded into HSM memory.")
    
    def sign_data(self, data: bytes) -> bytes:
        """
        Sign data using the private key stored in the HSM.
        The raw private key is NEVER returned to the caller.
        """
        if self._is_locked or self._private_key is None:
            raise RuntimeError("HSM is locked or no key loaded. Cannot sign.")
        
        print("[*] HSM performing digital signature operation...")
        
        # Perform RSA signing with PSS padding and SHA256
        signature = self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print("[+] Data signed successfully inside HSM.")
        return signature
    
    def get_public_key(self):
        """Extract the public key (it is safe to share the public key)."""
        if self._private_key is None:
            raise RuntimeError("No key loaded in HSM.")
        return self._private_key.public_key()

    def lock(self):
        """Lock the HSM, clearing the private key from memory."""
        self._private_key = None
        self._is_locked = True
        print("[+] HSM locked. Private key cleared from memory.")


# Example usage and testing
if __name__ == "__main__":
    print("=== Virtual HSM Test ===")
    
    # 1. Initialize the HSM
    hsm = VirtualHSM()
    
    # 2. Load the CA private key we generated in Step 2
    hsm.load_key_from_pem("certs/ca_key.pem")
    
    # 3. Sign a test message
    message = b"This is a highly confidential chat message from Alice to Bob."
    signature = hsm.sign_data(message)
    
    print(f"\nOriginal Message: {message.decode()}")
    print(f"Signature (Hex): {signature.hex()[:50]}...")
    
    # 4. Verify the signature using the public key
    public_key = hsm.get_public_key()
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n[+] Signature verified successfully using Public Key!")
    except Exception as e:
        print(f"\n[-] Signature verification failed: {e}")
    
    # 5. Lock the HSM
    hsm.lock()
    
    # 6. Try to sign again (should fail)
    try:
        hsm.sign_data(b"Another message")
    except RuntimeError as e:
        print(f"\n[+] Security check passed: {e}")
        
