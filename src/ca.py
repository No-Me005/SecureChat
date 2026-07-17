#!/usr/bin/env python3
"""
Certificate Authority Module
Generates Root CA and issues user certificates for the Secure PKI Chat Tool.
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class CertificateAuthority:
    """Manages the Certificate Authority for issuing and validating certificates."""
    
    def __init__(self, ca_dir="certs"):
        self.ca_dir = ca_dir
        self.ca_cert_path = os.path.join(ca_dir, "ca_cert.pem")
        self.ca_key_path = os.path.join(ca_dir, "ca_key.pem")
        self.backend = default_backend()
    
    def generate_root_ca(self):
        """Generate Root CA private key and self-signed certificate."""
        print("[*] Generating Root CA...")
        
        # Generate RSA private key (2048 bits)
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        
        # Create CA subject name
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Coventry"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Coventry University"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
        ])
        
        # Create CA certificate
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            )
            .sign(self.ca_private_key, hashes.SHA256(), self.backend)
        )
        
        # Create certs directory if it doesn't exist
        os.makedirs(self.ca_dir, exist_ok=True)
        
        # Save CA private key
        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save CA certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"[+] Root CA certificate saved to: {self.ca_cert_path}")
        print(f"[+] Root CA private key saved to: {self.ca_key_path}")
        return self.ca_cert, self.ca_private_key
    
    def load_ca(self):
        """Load existing CA certificate and private key."""
        if not os.path.exists(self.ca_cert_path) or not os.path.exists(self.ca_key_path):
            raise FileNotFoundError("CA certificate or key not found. Run generate_root_ca() first.")
        
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), self.backend)
        
        with open(self.ca_key_path, "rb") as f:
            self.ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=self.backend
            )
        
        print("[+] Root CA loaded successfully")
        return self.ca_cert, self.ca_private_key
    
    def issue_user_certificate(self, username, user_public_key, user_dir=None):
        """Issue a certificate for a user, signed by the CA."""
        print(f"[*] Issuing certificate for user: {username}")
        
        # Load CA if not already loaded
        if not hasattr(self, 'ca_cert'):
            self.load_ca()
        
        # Create user subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Coventry"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Coventry University"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat User"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        
        # Create user certificate
        user_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(user_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            )
            .sign(self.ca_private_key, hashes.SHA256(), self.backend)
        )
        
        # Set user directory
        if user_dir is None:
            user_dir = os.path.join(self.ca_dir, "users", username)
        
        os.makedirs(user_dir, exist_ok=True)
        
        # Save user certificate
        user_cert_path = os.path.join(user_dir, f"{username}_cert.pem")
        with open(user_cert_path, "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"[+] User certificate saved to: {user_cert_path}")
        return user_cert, user_cert_path
    
    def verify_certificate(self, cert_path):
        """Verify if a certificate was signed by our CA."""
        print(f"[*] Verifying certificate: {cert_path}")
        
        # Load CA if not already loaded
        if not hasattr(self, 'ca_cert'):
            self.load_ca()
        
        # Load the certificate to verify
        with open(cert_path, "rb") as f:
            cert_to_verify = x509.load_pem_x509_certificate(f.read(), self.backend)
        
        try:
            # Check if the issuer matches our CA
            if cert_to_verify.issuer != self.ca_cert.subject:
                print("[-] Certificate issuer does not match CA")
                return False
            
            # Verify the signature using proper padding
            self.ca_cert.public_key().verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm
            )
            print(f"[+] Certificate verified successfully!")
            print(f"    Subject: {cert_to_verify.subject}")
            print(f"    Issuer: {cert_to_verify.issuer}")
            return True
        except Exception as e:
            print(f"[-] Certificate verification failed: {e}")
            return False
