import os
import pytest
import sys
from io import StringIO
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from ca import CertificateAuthority

def show_result(name, passed):
    CYAN, GREEN, YELLOW, BOLD, RESET = "\033[36m", "\033[32m", "\033[93m", "\033[1m", "\033[0m"
    status = f"{BOLD}{GREEN}✓ PASSED{RESET}" if passed else f"{BOLD}{YELLOW}✗ FAILED{RESET}"
    print(f"{CYAN}{name}{RESET}  {YELLOW}⇒{RESET}  {status}")

def test_ca_generate_root(tmp_path):
    try:
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        ca = CertificateAuthority(ca_dir=str(tmp_path))
        ca.generate_root_ca()
        sys.stdout = old_stdout
        assert os.path.exists(os.path.join(str(tmp_path), "ca_cert.pem"))
        show_result("test_ca_generate_root", True)
    except Exception as e:
        sys.stdout = old_stdout
        show_result("test_ca_generate_root", False)
        raise

def test_ca_load_existing(tmp_path):
    try:
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        ca = CertificateAuthority(ca_dir=str(tmp_path))
        ca.generate_root_ca()
        ca2 = CertificateAuthority(ca_dir=str(tmp_path))
        ca2.load_ca()
        sys.stdout = old_stdout
        assert ca2.ca_cert is not None
        show_result("test_ca_load_existing", True)
    except Exception as e:
        sys.stdout = old_stdout
        show_result("test_ca_load_existing", False)
        raise

def test_ca_issue_and_verify(tmp_path):
    try:
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        ca = CertificateAuthority(ca_dir=str(tmp_path))
        ca.generate_root_ca()
        user_key = rsa.generate_private_key(65537, 2048, default_backend())
        cert, cert_path = ca.issue_user_certificate("testuser", user_key.public_key())
        result = ca.verify_certificate(cert_path)
        sys.stdout = old_stdout
        assert result == True
        show_result("test_ca_issue_and_verify", True)
    except Exception as e:
        sys.stdout = old_stdout
        show_result("test_ca_issue_and_verify", False)
        raise
