import os
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def show_result(name, passed):
    CYAN, GREEN, YELLOW, BOLD, RESET = "\033[36m", "\033[32m", "\033[93m", "\033[1m", "\033[0m"
    status = f"{BOLD}{GREEN}✓ PASSED{RESET}" if passed else f"{BOLD}{YELLOW}✗ FAILED{RESET}"
    print(f"{CYAN}{name}{RESET}  {YELLOW}⇒{RESET}  {status}")

def test_key_manager_module_loads():
    try:
        import key_manager
        assert key_manager is not None
        show_result("test_key_manager_module_loads", True)
    except Exception:
        show_result("test_key_manager_module_loads", False)
        raise

def test_key_generation_and_serialization():
    try:
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        assert b"-----BEGIN" in private_pem
        show_result("test_key_generation_and_serialization", True)
    except Exception:
        show_result("test_key_generation_and_serialization", False)
        raise
