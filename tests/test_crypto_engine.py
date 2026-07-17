import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def show_result(name, passed):
    CYAN, GREEN, YELLOW, BOLD, RESET = "\033[36m", "\033[32m", "\033[93m", "\033[1m", "\033[0m"
    status = f"{BOLD}{GREEN}✓ PASSED{RESET}" if passed else f"{BOLD}{YELLOW}✗ FAILED{RESET}"
    print(f"{CYAN}{name}{RESET}  {YELLOW}⇒{RESET}  {status}")

def test_aes_gcm_encrypt_decrypt():
    try:
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, b"Secure PKI Chat Message", None)
        assert AESGCM(key).decrypt(nonce, ciphertext, None) == b"Secure PKI Chat Message"
        show_result("test_aes_gcm_encrypt_decrypt", True)
    except Exception:
        show_result("test_aes_gcm_encrypt_decrypt", False)
        raise

def test_rsa_oaep_encrypt_decrypt():
    try:
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()
        ciphertext = public_key.encrypt(b"secret_key", padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        ))
        assert private_key.decrypt(ciphertext, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )) == b"secret_key"
        show_result("test_rsa_oaep_encrypt_decrypt", True)
    except Exception:
        show_result("test_rsa_oaep_encrypt_decrypt", False)
        raise

def test_crypto_engine_module():
    try:
        import crypto_engine
        assert crypto_engine is not None
        show_result("test_crypto_engine_module", True)
    except Exception:
        show_result("test_crypto_engine_module", False)
        raise
