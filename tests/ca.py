import os
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from ca import CertificateAuthority

def test_ca_generate_root(tmp_path):
    """Test Root CA certificate generation"""
    ca = CertificateAuthority(ca_dir=str(tmp_path))
    ca.generate_root_ca()
    assert os.path.exists(os.path.join(str(tmp_path), "ca_cert.pem"))
    assert os.path.exists(os.path.join(str(tmp_path), "ca_key.pem"))

def test_ca_load_existing(tmp_path):
    """Test loading existing CA certificate and key"""
    ca = CertificateAuthority(ca_dir=str(tmp_path))
    ca.generate_root_ca()
    
    ca2 = CertificateAuthority(ca_dir=str(tmp_path))
    ca2.load_ca()
    assert ca2.ca_cert is not None
    assert ca2.ca_private_key is not None

def test_ca_issue_and_verify(tmp_path):
    """Test issuing user certificate and verification"""
    ca = CertificateAuthority(ca_dir=str(tmp_path))
    ca.generate_root_ca()
    
    user_key = rsa.generate_private_key(65537, 2048, default_backend())
    cert, cert_path = ca.issue_user_certificate("testuser", user_key.public_key())
    
    assert os.path.exists(cert_path)
    assert ca.verify_certificate(cert_path) == True
