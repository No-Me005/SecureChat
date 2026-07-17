#!/usr/bin/env python3
"""
Secure Chat Server - FIXED Message Routing Protocol
Ensures compatibility with both CLI and GUI clients by stripping routing tags.
"""

import socket
import threading
import os
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class SecureChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.clients = {}
        self.user_public_keys = {}
        self.user_key_pems = {}
        self.ca_cert_path = "certs/ca_cert.pem"
        self.backend = default_backend()
        self.lock = threading.Lock()
        self.load_ca_certificate()

    def load_ca_certificate(self):
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), self.backend)
        print("[+] Server loaded CA certificate")

    def verify_client_certificate(self, cert_path):
        try:
            with open(cert_path, "rb") as f:
                client_cert = x509.load_pem_x509_certificate(f.read(), self.backend)
            if client_cert.issuer != self.ca_cert.subject:
                return False, "Not issued by trusted CA"
            username = None
            for attr in client_cert.subject:
                if attr.oid._name == "commonName":
                    username = attr.value
            return True, username
        except Exception as e:
            return False, str(e)

    def send_to_client(self, client_socket, message):
        try:
            client_socket.send((message + "\n").encode('utf-8'))
        except Exception as e:
            print(f"[-] Error sending to client: {e}")

    def handle_client(self, client_socket, address):
        username = None
        try:
            # Authentication
            cert_path = client_socket.recv(1024).decode('utf-8').strip()
            is_valid, result = self.verify_client_certificate(cert_path)

            if not is_valid:
                self.send_to_client(client_socket, "AUTH_FAILED")
                client_socket.close()
                return

            username = result

            with self.lock:
                self.clients[username] = client_socket

            self.send_to_client(client_socket, "AUTH_SUCCESS")
            print(f"[+] {username} authenticated from {address}")

            # Receive Public Key
            pub_key_raw = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    return
                pub_key_raw += chunk
                if b"\n" in pub_key_raw:
                    break

            pub_key_data = pub_key_raw.decode('utf-8').strip()

            if pub_key_data.startswith("PUBKEY:"):
                key_b64 = pub_key_data.split(":", 1)[1].strip()

                try:
                    der_bytes = base64.b64decode(key_b64)
                    pub_key = serialization.load_der_public_key(der_bytes, backend=self.backend)

                    with self.lock:
                        self.user_public_keys[username] = pub_key
                        self.user_key_pems[username] = key_b64

                    # Send existing users' keys to new user
                    with self.lock:
                        for existing_user, existing_key_b64 in self.user_key_pems.items():
                            if existing_user != username:
                                msg = f"EXISTINGUSER:{existing_user}:{existing_key_b64}"
                                self.send_to_client(client_socket, msg)
                                print(f"[*] Sent {existing_user}'s key to {username}")

                        # Broadcast new user's key to all existing users
                        broadcast_msg = f"NEWUSER:{username}:{key_b64}"
                        for other_user, other_socket in self.clients.items():
                            if other_user != username:
                                self.send_to_client(other_socket, broadcast_msg)
                                print(f"[*] Sent {username}'s key to {other_user}")

                    print(f"[+] Key distribution complete for {username}")
                except Exception as e:
                    print(f"[-] Error processing public key for {username}: {e}")
                    self.send_to_client(client_socket, "ERROR:Key processing failed")

            # Message Routing - FIXED to strip msg_type tag
            buffer = ""
            while True:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    buffer += data.decode('utf-8')
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue

                        if line.startswith("TO:"):
                            parts = line.split(":", 3)
                            if len(parts) >= 4:
                                target_user = parts[1]
                                # msg_type = parts[2]  # We intentionally ignore this tag
                                encrypted_payload = parts[3]

                                with self.lock:
                                    if target_user in self.clients:
                                        # FIX: Forward ONLY sender and payload (3 parts total)
                                        # Both CLI and GUI expect: FROM:sender:payload
                                        forward_msg = f"FROM:{username}:{encrypted_payload}"
                                        try:
                                            self.send_to_client(self.clients[target_user], forward_msg)
                                            print(f"[*] Routed: {username} -> {target_user} ({len(encrypted_payload)} bytes)")
                                        except Exception as e:
                                            print(f"[-] Error routing message: {e}")
                                            self.send_to_client(client_socket, f"ERROR:Failed to route message")
                                    else:
                                        self.send_to_client(client_socket, f"ERROR:User {target_user} not online")
                        else:
                            # Broadcast message
                            with self.lock:
                                for other_user, other_socket in self.clients.items():
                                    if other_user != username:
                                        try:
                                            self.send_to_client(other_socket, f"[{username}]: {line}")
                                        except:
                                            pass

                except Exception as e:
                    print(f"[-] Error receiving from {username}: {e}")
                    break

        except Exception as e:
            print(f"[-] Error with {username}: {e}")
        finally:
            with self.lock:
                if username in self.clients:
                    del self.clients[username]
                if username in self.user_public_keys:
                    del self.user_public_keys[username]
                if username in self.user_key_pems:
                    del self.user_key_pems[username]
                for other_user, other_socket in list(self.clients.items()):
                    try:
                        self.send_to_client(other_socket, f"[SERVER] {username} has left")
                    except:
                        pass
            client_socket.close()
            print(f"[*] {username} disconnected")

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print("=" * 50)
        print("Secure Chat Server Started")
        print(f"Listening on {self.host}:{self.port}")
        print("=" * 50)
        while True:
            client_socket, address = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()

if __name__ == "__main__":
    SecureChatServer().start()
