#!/usr/bin/env python3
"""
Secure Chat GUI Client - Fixed Message Parsing for 3-Part Protocol
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import base64
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure PKI Chat Tool")
        self.root.geometry("1100x700")
        self.root.configure(bg="#2c3e50")
        self.root.minsize(900, 600)
        
        self.colors = {
            'bg_primary': '#2c3e50', 'bg_secondary': '#34495e', 'bg_sidebar': '#1a252f',
            'accent': '#27ae60', 'text_primary': '#ecf0f1', 'text_secondary': '#95a5a6',
            'warning': '#f39c12', 'error': '#e74c3c'
        }

        self.backend = default_backend()
        self.session_private_key = None
        self.known_public_keys = {}
        self.online_users = set()
        self.sock = None
        self.username = None
        self.running = False
        self.users_listbox = None

        self.setup_login_frame()

    def setup_login_frame(self):
        self.login_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        self.login_frame.pack(expand=True, fill="both")

        card = tk.Frame(self.login_frame, bg=self.colors['bg_secondary'], padx=80, pady=60)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="", font=("Helvetica", 72), bg=self.colors['bg_secondary']).pack(pady=(0, 20))
        tk.Label(card, text="Secure PKI Chat", font=("Helvetica", 32, "bold"), 
                fg=self.colors['text_primary'], bg=self.colors['bg_secondary']).pack(pady=(0, 10))
        tk.Label(card, text="End-to-End Encrypted Messaging", font=("Helvetica", 12), 
                fg=self.colors['text_secondary'], bg=self.colors['bg_secondary']).pack(pady=(0, 50))

        tk.Label(card, text="USERNAME", font=("Helvetica", 10, "bold"), 
                fg=self.colors['text_secondary'], bg=self.colors['bg_secondary'], anchor="w").pack(fill="x", pady=(0, 8))
        
        self.username_entry = tk.Entry(card, font=("Helvetica", 14), width=30, 
                                      bg=self.colors['bg_primary'], fg=self.colors['text_primary'],
                                      relief=tk.FLAT, bd=0, insertbackground=self.colors['text_primary'])
        self.username_entry.pack(fill="x", pady=(0, 30), ipady=8)
        self.username_entry.focus()

        self.connect_btn = tk.Button(card, text="CONNECT TO SERVER", command=self.connect_to_server, 
                                    font=("Helvetica", 12, "bold"), bg=self.colors['accent'], 
                                    fg="white", width=30, relief=tk.FLAT, cursor="hand2", pady=12)
        self.connect_btn.pack(pady=(0, 20))

        self.status_label = tk.Label(card, text="", font=("Helvetica", 9), 
                                    fg=self.colors['error'], bg=self.colors['bg_secondary'])
        self.status_label.pack()

    def setup_chat_frame(self):
        self.login_frame.destroy()

        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(expand=True, fill="both")

        # LEFT SIDEBAR
        self.sidebar = tk.Frame(main_container, bg=self.colors['bg_sidebar'], width=300)
        self.sidebar.pack(side="left", fill="both", padx=(10, 0), pady=10)
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text=" Secure Chat", font=("Helvetica", 16, "bold"), 
                fg=self.colors['text_primary'], bg=self.colors['bg_sidebar']).pack(pady=20)

        user_info = tk.Frame(self.sidebar, bg=self.colors['bg_secondary'], padx=15, pady=10)
        user_info.pack(fill="x", padx=10, pady=(0, 10))
        
        tk.Label(user_info, text="Logged in as:", font=("Helvetica", 9), 
                fg=self.colors['text_secondary'], bg=self.colors['bg_secondary']).pack(anchor="w")
        tk.Label(user_info, text=self.username, font=("Helvetica", 12, "bold"), 
                fg=self.colors['text_primary'], bg=self.colors['bg_secondary']).pack(anchor="w")

        tk.Label(self.sidebar, text="ONLINE USERS", font=("Helvetica", 10, "bold"), 
                fg=self.colors['text_secondary'], bg=self.colors['bg_sidebar']).pack(fill="x", padx=10, pady=(10, 5))

        users_frame = tk.Frame(self.sidebar, bg=self.colors['bg_sidebar'])
        users_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.users_listbox = tk.Listbox(users_frame, font=("Helvetica", 11),
                                       bg=self.colors['bg_secondary'], fg=self.colors['text_primary'],
                                       selectbackground=self.colors['accent'], selectforeground="white",
                                       relief=tk.FLAT, bd=0, highlightthickness=0)
        self.users_listbox.pack(fill="both", expand=True)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        # RIGHT PANEL
        self.chat_panel = tk.Frame(main_container, bg=self.colors['bg_primary'])
        self.chat_panel.pack(side="right", expand=True, fill="both", padx=10, pady=10)

        chat_header = tk.Frame(self.chat_panel, bg=self.colors['bg_secondary'], height=70)
        chat_header.pack(fill="x")
        chat_header.pack_propagate(False)
        
        self.chat_with_label = tk.Label(chat_header, text="Select a user to start chatting", 
                                       font=("Helvetica", 14, "bold"),
                                       fg=self.colors['text_primary'], bg=self.colors['bg_secondary'])
        self.chat_with_label.pack(side="left", padx=20, pady=25)

        tk.Button(chat_header, text="Disconnect", command=self.disconnect, 
                 bg=self.colors['error'], fg="white", font=("Helvetica", 9, "bold"),
                 relief=tk.FLAT, cursor="hand2", padx=15, pady=5).pack(side="right", padx=10)

        messages_frame = tk.Frame(self.chat_panel, bg=self.colors['bg_secondary'])
        messages_frame.pack(expand=True, fill="both", pady=(10, 0))

        self.chat_display = scrolledtext.ScrolledText(messages_frame, wrap=tk.WORD, 
                                                     font=("Consolas", 11), 
                                                     bg=self.colors['bg_primary'], 
                                                     fg=self.colors['text_primary'], 
                                                     state="disabled", relief=tk.FLAT, 
                                                     padx=20, pady=20, borderwidth=0)
        self.chat_display.pack(expand=True, fill="both", padx=10, pady=10)

        input_container = tk.Frame(self.chat_panel, bg=self.colors['bg_secondary'], height=80)
        input_container.pack(fill="x", pady=(10, 0))
        input_container.pack_propagate(False)

        tk.Label(input_container, text="To:", font=("Helvetica", 11, "bold"), 
                fg=self.colors['text_secondary'], bg=self.colors['bg_secondary']).pack(side="left", padx=(15, 5), pady=25)
        
        self.recipient_entry = tk.Entry(input_container, font=("Helvetica", 11), width=15, 
                                       bg=self.colors['bg_primary'], fg=self.colors['text_primary'],
                                       relief=tk.FLAT, bd=0)
        self.recipient_entry.pack(side="left", padx=(0, 15), pady=25)

        self.message_entry = tk.Entry(input_container, font=("Helvetica", 11), 
                                     bg=self.colors['bg_primary'], fg=self.colors['text_primary'],
                                     relief=tk.FLAT, bd=0)
        self.message_entry.pack(side="left", expand=True, fill="x", padx=(0, 10), pady=25)
        self.message_entry.bind("<Return>", lambda e: self.send_message_gui())

        tk.Button(input_container, text="Send Encrypted 🔐", command=self.send_message_gui, 
                 bg=self.colors['accent'], fg="white", font=("Helvetica", 11, "bold"),
                 relief=tk.FLAT, cursor="hand2", padx=20, pady=10).pack(side="right", padx=(0, 15), pady=20)

        self.log_message("=" * 60, "system")
        self.log_message("Welcome to Secure PKI Chat!", "system")
        self.log_message("All messages are end-to-end encrypted", "system")
        self.log_message("=" * 60, "system")

    def on_user_select(self, event):
        selection = self.users_listbox.curselection()
        if selection:
            index = selection[0]
            user = self.users_listbox.get(index).split(" ●")[0].split(" (You)")[0]
            if user and user != self.username:
                self.recipient_entry.delete(0, tk.END)
                self.recipient_entry.insert(0, user)
                self.chat_with_label.config(text=f"Chat with {user}")
                self.log_message(f"\n--- Starting encrypted chat with {user} ---\n", "system")

    def update_users_list(self):
        def _update():
            if not hasattr(self, 'users_listbox') or self.users_listbox is None:
                return
                
            self.users_listbox.delete(0, tk.END)
            for user in sorted(self.online_users):
                if user == self.username:
                    display = f"{user} (You)"
                else:
                    display = f"{user} ●"
                self.users_listbox.insert(tk.END, display)
        
        self.root.after(0, _update)

    def log_message(self, text, msg_type="normal"):
        def _update():
            if not hasattr(self, 'chat_display'):
                return 
            self.chat_display.config(state="normal")
            if msg_type == "system":
                self.chat_display.insert(tk.END, text + "\n", "system")
            elif msg_type == "sent":
                self.chat_display.insert(tk.END, text + "\n", "sent")
            elif msg_type == "received":
                self.chat_display.insert(tk.END, text + "\n", "received")
            elif msg_type == "error":
                self.chat_display.insert(tk.END, text + "\n", "error")
            else:
                self.chat_display.insert(tk.END, text + "\n")
            self.chat_display.see(tk.END)
            self.chat_display.config(state="disabled")
        self.root.after(0, _update)

    def connect_to_server(self):
        self.username = self.username_entry.get().strip()
        if not self.username:
            self.status_label.config(text="Please enter a username!")
            return

        cert_path = f"certs/users/{self.username}/{self.username}_cert.pem"
        key_path = f"certs/users/{self.username}/{self.username}_key.pem"

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            self.status_label.config(text=f"Certificates not found for '{self.username}'!")
            return

        self.status_label.config(text="Connecting...", fg=self.colors['warning'])
        self.connect_btn.config(state="disabled")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.connect(('127.0.0.1', 5555))
            
            self.sock.sendall((cert_path + "\n").encode('utf-8'))
            response = self.sock.recv(1024).decode('utf-8').strip()

            if response == "AUTH_SUCCESS":
                self.status_label.config(text="Authenticated!", fg=self.colors['accent'])
                
                self.session_private_key = rsa.generate_private_key(65537, 2048, self.backend)
                session_public_key = self.session_private_key.public_key()

                der_bytes = session_public_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                key_b64 = base64.b64encode(der_bytes).decode('utf-8')
                self.sock.sendall((f"PUBKEY:{key_b64}\n").encode('utf-8'))

                self.online_users.add(self.username)
                
                # Setup UI IMMEDIATELY before starting the listener thread
                self.setup_chat_frame()
                self.update_users_list() # Show self immediately
                
                self.running = True
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.status_label.config(text=f"Auth failed: {response}", fg=self.colors['error'])
                self.sock.close()
                self.connect_btn.config(state="normal")

        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)[:40]}", fg=self.colors['error'])
            self.connect_btn.config(state="normal")

    def receive_messages(self):
        buffer = ""
        while self.running:
            try:
                self.sock.settimeout(30)
                data = self.sock.recv(4096)
                if not data: break
                    
                buffer += data.decode('utf-8')
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line: continue

                    # Handle User Presence Updates
                    if line.startswith("NEWUSER:") or line.startswith("EXISTINGUSER:"):
                        parts = line.split(":", 2)
                        if len(parts) == 3:
                            user, key_b64 = parts[1], parts[2]
                            try:
                                der_bytes = base64.b64decode(key_b64)
                                pub_key = serialization.load_der_public_key(der_bytes, backend=self.backend)
                                self.known_public_keys[user] = pub_key
                                self.online_users.add(user)
                                self.update_users_list()
                                if line.startswith("NEWUSER:"):
                                    self.log_message(f"✓ {user} is now online", "system")
                            except Exception as e:
                                print(f"[GUI DEBUG] Key Error: {e}")

                    # FIXED: Handle Incoming Messages (Strict 3-Part Split)
                    elif line.startswith("FROM:"):
                        # Server sends: FROM:sender:payload
                        # Payload contains colons, so we MUST limit split to 2
                        parts = line.split(":", 2) 
                        
                        if len(parts) == 3:
                            sender = parts[1]
                            payload = parts[2]
                            
                            # Debug print to verify receipt in terminal
                            print(f"[GUI DEBUG] Received from {sender}, Payload length: {len(payload)}")

                            try:
                                decrypted = self.decrypt_message(payload)
                                timestamp = datetime.now().strftime("%H:%M:%S")
                                self.log_message(f"[{timestamp}] {sender}: {decrypted}", "received")
                            except Exception as e:
                                # Show error in chat so you know decryption failed
                                self.log_message(f"⚠️ Decryption failed for msg from {sender}: {str(e)[:30]}", "error")
                                print(f"[GUI DEBUG] Decrypt Error: {e}")
                        else:
                            print(f"[GUI DEBUG] Malformed FROM message received: {line}")

                    elif line.startswith("[SERVER]"):
                        self.log_message(line, "system")
                    elif line.startswith("ERROR:"):
                        self.log_message(line[6:], "error")

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log_message("Connection lost", "error")
                break

    def encrypt_for_user(self, message_bytes, target_username):
        if target_username not in self.known_public_keys: return None
        recipient_pub_key = self.known_public_keys[target_username]
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, message_bytes, None)
        encrypted_aes_key = recipient_pub_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return f"{encrypted_aes_key.hex()}:{nonce.hex()}:{ciphertext.hex()}"

    def decrypt_message(self, payload):
        parts = payload.split(":")
        if len(parts) != 3: raise ValueError(f"Invalid payload format: expected 3 parts, got {len(parts)}")
        enc_aes_key = bytes.fromhex(parts[0])
        nonce = bytes.fromhex(parts[1])
        ciphertext = bytes.fromhex(parts[2])
        aes_key = self.session_private_key.decrypt(enc_aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode('utf-8')

    def send_message_gui(self):
        target = self.recipient_entry.get().strip()
        msg = self.message_entry.get().strip()
        if not target or not msg: return
        if target not in self.known_public_keys:
            self.log_message(f"✗ Cannot send to {target}. User not found.", "error")
            return
        try:
            payload = self.encrypt_for_user(msg.encode('utf-8'), target)
            self.sock.sendall(f"TO:{target}:MSG:{payload}\n".encode('utf-8'))
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_message(f"[{timestamp}] You: {msg} 🔐", "sent")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.log_message(f"Send failed: {e}", "error")

    def disconnect(self):
        if messagebox.askyesno("Disconnect", "Are you sure?", parent=self.root):
            self.running = False
            if self.sock: self.sock.close()
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatGUI(root)
    root.mainloop()
