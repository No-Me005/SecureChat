#!/usr/bin/env python3
"""
Secure Chat Client - FIXED with proper key exchange and decryption
"""

import socket
import threading
import sys
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class SecureChatClient:
    def __init__(self, username, cert_path, key_path, server_host='127.0.0.1', server_port=5555):
        self.username = username
        self.cert_path = cert_path
        self.key_path = key_path
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None
        self.backend = default_backend()
        self.session_private_key = None
        self.known_public_keys = {}  # {username: public_key_object}
        self.running = True

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            print(f"[*] Connected to server")

            # Send certificate path
            self.sock.send((self.cert_path + "\n").encode('utf-8'))

            # Receive auth response
            response = self.sock.recv(1024).decode('utf-8').strip()
            if response == "AUTH_SUCCESS":
                print(f"[+] Authenticated as {self.username}")

                # Generate ephemeral session key pair
                self.session_private_key = rsa.generate_private_key(65537, 2048, self.backend)
                session_public_key = self.session_private_key.public_key()

                # Convert public key to DER -> base64 (single line, safe for TCP)
                der_bytes = session_public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
                key_b64 = base64.b64encode(der_bytes).decode('utf-8')

                # Send public key as single line
                self.sock.send((f"PUBKEY:{key_b64}\n").encode('utf-8'))
                print("[+] Public key shared with server")
                return True
            else:
                print(f"[-] Auth failed: {response}")
                return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False

    def store_public_key(self, username, key_b64):
        """Decode base64 DER key and store it."""
        try:
            der_bytes = base64.b64decode(key_b64)
            pub_key = serialization.load_der_public_key(der_bytes, backend=self.backend)
            self.known_public_keys[username] = pub_key
            print(f"  [KEY] Stored public key for {username}")
        except Exception as e:
            print(f"  [KEY ERROR] Failed to store key for {username}: {e}")

    def encrypt_for_user(self, message_bytes, target_username):
        """Hybrid encrypt: only target user can decrypt."""
        if target_username not in self.known_public_keys:
            return None, f"Key not found for {target_username}. Known keys: {list(self.known_public_keys.keys())}"

        recipient_pub_key = self.known_public_keys[target_username]

        # 1. Random AES-256 key
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        # 2. Encrypt message with AES
        ciphertext = AESGCM(aes_key).encrypt(nonce, message_bytes, None)

        # 3. Encrypt AES key with recipient's RSA public key
        encrypted_aes_key = recipient_pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Package as hex
        payload = f"{encrypted_aes_key.hex()}:{nonce.hex()}:{ciphertext.hex()}"
        return payload, None

    def decrypt_message(self, payload):
        """Hybrid decrypt using our private key."""
        parts = payload.split(":")
        if len(parts) != 3:
            raise ValueError("Invalid payload format")

        enc_aes_key = bytes.fromhex(parts[0])
        nonce = bytes.fromhex(parts[1])
        ciphertext = bytes.fromhex(parts[2])

        # 1. Decrypt AES key with our private key
        aes_key = self.session_private_key.decrypt(
            enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Decrypt message with AES
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

    def receive_messages(self):
        """Receive and process messages line by line."""
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break

                buffer += data.decode('utf-8')
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    if line.startswith("NEWUSER:"):
                        parts = line.split(":", 2)
                        if len(parts) == 3:
                            new_user = parts[1]
                            key_b64 = parts[2]
                            self.store_public_key(new_user, key_b64)
                            print(f"\n[SYSTEM] {new_user} joined the chat")

                    elif line.startswith("EXISTINGUSER:"):
                        parts = line.split(":", 2)
                        if len(parts) == 3:
                            existing_user = parts[1]
                            key_b64 = parts[2]
                            self.store_public_key(existing_user, key_b64)

                    elif line.startswith("FROM:"):
                        parts = line.split(":", 2)
                        if len(parts) == 3:
                            sender = parts[1]
                            encrypted_payload = parts[2]
                            try:
                                decrypted = self.decrypt_message(encrypted_payload)
                                print(f"\n🔓 [{sender}]: {decrypted}")
                            except Exception as e:
                                print(f"\n🔒 [{sender}]: (Encrypted - cannot decrypt: {e})")

                    elif line.startswith("ERROR:"):
                        print(f"\n[ERROR] {line[6:]}")

                    else:
                        print(f"\n{line}")

            except Exception as e:
                if self.running:
                    print(f"[-] Receive error: {e}")
                break

        print("\n[*] Disconnected from server")

    def send_message(self, target_user, message_text):
        """Encrypt and send a private message."""
        payload, error = self.encrypt_for_user(message_text.encode('utf-8'), target_user)
        if error:
            print(f"[-] {error}")
            return

        full_msg = f"TO:{target_user}:MSG:{payload}"
        self.sock.send((full_msg + "\n").encode('utf-8'))
        print(f"[+] Encrypted message sent to {target_user}")

    def start(self):
        if not self.connect():
            return

        threading.Thread(target=self.receive_messages, daemon=True).start()

        print("\n" + "=" * 50)
        print("Secure Chat Ready")
        print("Commands:")
        print("  /msg <username> <message>  - Send encrypted message")
        print("  /users                     - Show known public keys")
        print("  /quit                      - Exit")
        print("=" * 50 + "\n")

        while self.running:
            try:
                msg = input()
            except EOFError:
                break

            if msg.startswith("/quit"):
                self.running = False
                self.sock.close()
                print("[+] Goodbye!")
                sys.exit(0)

            elif msg.startswith("/msg"):
                parts = msg.split(" ", 2)
                if len(parts) >= 3:
                    self.send_message(parts[1], parts[2])
                else:
                    print("Usage: /msg <username> <message>")

            elif msg.startswith("/users"):
                print(f"\nKnown public keys: {list(self.known_public_keys.keys())}")

            else:
                print("Unknown command. Use /msg, /users, or /quit")


def main():
    print("=" * 50)
    print("Secure PKI Chat Client")
    print("=" * 50)

    username = input("\nEnter username: ").strip()
    cert_path = f"certs/users/{username}/{username}_cert.pem"
    key_path = f"certs/users/{username}/{username}_key.pem"

    if not os.path.exists(cert_path):
        print(f"[-] Certificate not found at {cert_path}")
        sys.exit(1)

    if not os.path.exists(key_path):
        print(f"[-] Private key not found at {key_path}")
        sys.exit(1)

    client = SecureChatClient(username, cert_path, key_path)
    client.start()


if __name__ == "__main__":
    main()
