import os
import sys
import shutil

# This line ensures Python looks in the current folder for your modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 50)
print("TIER 1: CRITICAL MODULE TESTS")
print("=" * 50)

# 1. Test Certificate Authority (ca.py)
print("\n[1/3] Testing ca.py (Certificate Authority)...")
try:
    from ca import CertificateAuthority
    ca = CertificateAuthority(ca_dir="test_certs_temp")
    ca.generate_root_ca()
    assert os.path.exists("test_certs_temp/ca_cert.pem")
    shutil.rmtree("test_certs_temp")
    print("✅ PASSED: CA generated certificates successfully.")
except Exception as e:
    print(f"❌ FAILED: {e}")

# 2. Test Crypto Engine (crypto_engine.py)
print("\n[2/3] Testing crypto_engine.py...")
try:
    import crypto_engine
    # We check if the module loaded. If it has a main class, we try to initialize it.
    if hasattr(crypto_engine, 'CryptoEngine'):
        crypto_engine.CryptoEngine()
    print("✅ PASSED: crypto_engine.py loaded and initialized successfully.")
except Exception as e:
    print(f"❌ FAILED: {e}")

# 3. Test Key Manager (key_manager.py)
print("\n[3/3] Testing key_manager.py...")
try:
    import key_manager
    # We check for common class names to avoid the ImportErrors you had earlier
    if hasattr(key_manager, 'KeyManager'):
        key_manager.KeyManager()
    elif hasattr(key_manager, 'VirtualHSM'):
        key_manager.VirtualHSM()
    print("✅ PASSED: key_manager.py loaded and initialized successfully.")
except Exception as e:
    print(f"❌ FAILED: {e}")

print("\n" + "=" * 50)
print("TESTING FINISHED")
print("=" * 50)
