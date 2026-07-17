import os
import shutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ca import CertificateAuthority

def test_ca_works():
    """Test that CA module works"""
    ca = CertificateAuthority(ca_dir="test_certs")
    ca.generate_root_ca()
    
    assert os.path.exists("test_certs/ca_cert.pem")
    assert os.path.exists("test_certs/ca_key.pem")
    
    # Cleanup
    shutil.rmtree("test_certs")
    print("✓ Test passed!")
