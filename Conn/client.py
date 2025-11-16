#!/usr/bin/env python3
"""
SecureChat Client
Connects to server, authenticates, and enables encrypted messaging.
"""

import socket
import json
import os
import sys
import time
import threading
import select
from datetime import datetime
from dotenv import load_dotenv
from cryptography import x509 
from crypto_utils import CryptoUtils, hash_password

# Load environment variables
load_dotenv()

class SecureChatClient:
    """Secure Chat Client"""
    
    def __init__(self):
        """Initialize client"""
        self.host = os.getenv('SERVER_HOST', 'localhost')
        self.port = int(os.getenv('SERVER_PORT', 5555))
        self.socket = None
        
        # Load certificates
        print("[+] Loading client certificates...")
        self.ca_cert = CryptoUtils.load_certificate(os.getenv('CA_CERT_PATH', 'certs/ca.crt'))
        self.client_cert = CryptoUtils.load_certificate(os.getenv('CLIENT_CERT_PATH', 'certs/client.crt'))
        self.client_key = CryptoUtils.load_private_key(os.getenv('CLIENT_KEY_PATH', 'certs/client.key'))
        
        # Session state
        self.session_key = None
        self.server_cert = None
        self.username = None
        self.sequence_number = 0
        self.server_sequence_number = 0
        
        # Transcript
        self.transcript = []
        self.transcript_file = None
        
        # Chat control
        self.chat_active = False
        
        print("[+] Client initialized successfully")
    
    def connect(self):
        """Connect to server"""
        try:
            print(f"\n[+] Connecting to {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print("[✓] Connected to server")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def start(self):
        """Start client and run protocol"""
        if not self.connect():
            return
        
        try:
            # Phase 1: Certificate Exchange
            if not self.handle_certificate_exchange():
                print("[!] Certificate exchange failed")
                return
            
            # Phase 2: Authentication
            if not self.handle_authentication():
                print("[!] Authentication failed")
                return
            
            # Phase 3: Key Agreement
            if not self.handle_key_agreement():
                print("[!] Key agreement failed")
                return
            
            # Phase 4: Chat Session
            self.handle_chat_session()
            
            # Phase 5: Session Closure
            self.handle_session_closure()
        
        except Exception as e:
            print(f"[!] Client error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()
    
    # ========== PHASE 1: CERTIFICATE EXCHANGE ==========
    
    def handle_certificate_exchange(self):
        """Exchange certificates with server and validate"""
        print("\n" + "="*60)
        print("PHASE 1: CERTIFICATE EXCHANGE & VALIDATION")
        print("="*60)
        
        try:
            # Send client hello with certificate
            client_hello = {
                'type': 'hello',
                'client_cert': CryptoUtils.certificate_to_pem(self.client_cert),
                'nonce': CryptoUtils.generate_random_bytes(16).hex()
            }
            self.send_message(client_hello)
            print("[+] Sent client hello with certificate")
            
            # Receive server hello
            data = self.receive_message()
            if not data or data.get('type') != 'server_hello':
                print("[!] Expected 'server_hello' message")
                return False
            
            print("[+] Received server hello")
            
            # Extract and validate server certificate
            server_cert_pem = data.get('server_cert')
            if not server_cert_pem:
                print("[!] Missing server certificate")
                return False
            
            # Parse certificate
            try:
                self.server_cert = CryptoUtils.pem_to_certificate(server_cert_pem)
                print(f"[+] Server certificate received (CN: {self.server_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value})")
            except Exception as e:
                print(f"[!] Failed to parse server certificate: {e}")
                return False
            
            # Validate server certificate
            is_valid, error_msg = CryptoUtils.validate_certificate(self.server_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] Server certificate validation failed: {error_msg}")
                print("[!] BAD_CERT: Cannot proceed with untrusted server")
                return False
            
            print("[✓] Server certificate validated successfully")
            return True
        
        except Exception as e:
            print(f"[!] Certificate exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ========== PHASE 2: AUTHENTICATION ==========
    
    def handle_authentication(self):
        """Handle user registration or login"""
        print("\n" + "="*60)
        print("PHASE 2: AUTHENTICATION")
        print("="*60)
        
        try:
            # Receive temporary DH parameters for credential encryption
            data = self.receive_message()
            if not data or data.get('type') != 'dh_init':
                print("[!] Expected DH initialization")
                return False
            
            p = data['p']
            g = data['g']
            server_B = data['B']
            
            print("[+] Received temporary DH parameters for credential encryption")
            
            # Generate client DH keys
            import secrets
            client_private = int.from_bytes(secrets.token_bytes(256), 'big') % (p - 2) + 2
            client_A = pow(g, client_private, p)
            
            # Send client's public key
            dh_response = {
                'type': 'dh_response',
                'A': client_A
            }
            self.send_message(dh_response)
            print("[+] Sent client DH public key")
            
            # Compute shared secret and derive AES key
            shared_secret = CryptoUtils.compute_dh_shared_secret(client_private, server_B, p)
            temp_aes_key = CryptoUtils.derive_aes_key_from_dh(shared_secret)
            print("[+] Temporary AES key derived for credential protection")
            
            # Ask user for action
            print("\n" + "-"*60)
            print("1. Register new account")
            print("2. Login to existing account")
            print("-"*60)
            
            choice = input("Select option (1 or 2): ").strip()
            
            if choice == '1':
                success = self.handle_registration(temp_aes_key)
            elif choice == '2':
                success = self.handle_login(temp_aes_key)
            else:
                print("[!] Invalid choice")
                return False
            
            return success
        
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_registration(self, aes_key):
        """Handle user registration"""
        try:
            print("\n" + "="*60)
            print("USER REGISTRATION")
            print("="*60)
            
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            confirm_password = input("Confirm Password: ").strip()
            
            # Validate input
            if not all([email, username, password]):
                print("[!] All fields are required")
                return False
            
            if password != confirm_password:
                print("[!] Passwords do not match")
                return False
            
            if len(password) < 8:
                print("[!] Password must be at least 8 characters")
                return False
            
            # Prepare credentials
            credentials = {
                'email': email,
                'username': username,
                'password': password
            }
            
            # Encrypt credentials
            encrypted = CryptoUtils.aes_encrypt(aes_key, json.dumps(credentials))
            
            # Send registration request
            register_msg = {
                'type': 'register',
                'encrypted_data': encrypted
            }
            self.send_message(register_msg)
            print("[+] Registration request sent (encrypted)")
            
            # Receive response
            response_msg = self.receive_message()
            if not response_msg or response_msg.get('type') != 'encrypted_response':
                print("[!] Invalid response from server")
                return False
            
            # Decrypt response
            encrypted_data = response_msg.get('encrypted_data')
            decrypted = CryptoUtils.aes_decrypt(
                aes_key,
                encrypted_data['iv'],
                encrypted_data['ciphertext']
            )
            response = json.loads(decrypted.decode('utf-8'))
            
            if response.get('success'):
                print(f"[✓] {response.get('message')}")
                self.username = username
                return True
            else:
                print(f"[!] Registration failed: {response.get('message')}")
                return False
        
        except Exception as e:
            print(f"[!] Registration error: {e}")
            return False
    
    def handle_login(self, aes_key):
        """Handle user login"""
        try:
            print("\n" + "="*60)
            print("USER LOGIN")
            print("="*60)
            
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            
            if not all([email, password]):
                print("[!] Email and password are required")
                return False
            
            # Prepare credentials
            credentials = {
                'email': email,
                'password': password
            }
            
            # Encrypt credentials
            encrypted = CryptoUtils.aes_encrypt(aes_key, json.dumps(credentials))
            
            # Send login request
            login_msg = {
                'type': 'login',
                'encrypted_data': encrypted
            }
            self.send_message(login_msg)
            print("[+] Login request sent (encrypted)")
            
            # Receive response
            response_msg = self.receive_message()
            if not response_msg or response_msg.get('type') != 'encrypted_response':
                print("[!] Invalid response from server")
                return False
            
            # Decrypt response
            encrypted_data = response_msg.get('encrypted_data')
            decrypted = CryptoUtils.aes_decrypt(
                aes_key,
                encrypted_data['iv'],
                encrypted_data['ciphertext']
            )
            response = json.loads(decrypted.decode('utf-8'))
            
            if response.get('success'):
                print(f"[✓] {response.get('message')}")
                self.username = response.get('username')
                return True
            else:
                print(f"[!] Login failed: {response.get('message')}")
                return False
        
        except Exception as e:
            print(f"[!] Login error: {e}")
            return False
    
    # ========== PHASE 3: KEY AGREEMENT ==========
    
    def handle_key_agreement(self):
        """Handle Diffie-Hellman key exchange for chat session"""
        print("\n" + "="*60)
        print("PHASE 3: KEY AGREEMENT (DIFFIE-HELLMAN)")
        print("="*60)
        
        try:
            # Generate DH parameters
            print("[+] Generating DH parameters...")
            dh_params = CryptoUtils.generate_dh_parameters()
            
            # Send DH parameters to server
            dh_client_msg = {
                'type': 'dh_client',
                'p': dh_params['p'],
                'g': dh_params['g'],
                'A': dh_params['public']
            }
            self.send_message(dh_client_msg)
            print("[+] Sent DH parameters to server")
            print(f"    p: {str(dh_params['p'])[:50]}... ({dh_params['p'].bit_length()} bits)")
            print(f"    g: {dh_params['g']}")
            print(f"    A: {str(dh_params['public'])[:50]}...")
            
            # Receive server's DH public key
            data = self.receive_message()
            if not data or data.get('type') != 'dh_server':
                print("[!] Invalid DH server response")
                return False
            
            server_B = data['B']
            print("[+] Received server DH public key")
            print(f"    B: {str(server_B)[:50]}...")
            
            # Compute shared secret
            shared_secret = CryptoUtils.compute_dh_shared_secret(
                dh_params['private'],
                server_B,
                dh_params['p']
            )
            
            # Derive session key
            self.session_key = CryptoUtils.derive_aes_key_from_dh(shared_secret)
            print("[✓] Session key established")
            print(f"    Key (hex): {self.session_key.hex()}")
            
            # Initialize transcript
            self.init_transcript()
            
            return True
        
        except Exception as e:
            print(f"[!] Key agreement error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ========== PHASE 4: CHAT SESSION ==========
    
    def handle_chat_session(self):
        """Handle encrypted chat session"""
        print("\n" + "="*60)
        print("PHASE 4: ENCRYPTED CHAT SESSION")
        print("="*60)
        
        # Wait for chat ready signal
        data = self.receive_message()
        if data and data.get('type') == 'chat_ready':
            print(f"[+] {data.get('message')}")
        
        print(f"[+] Logged in as: {self.username}")
        print("[+] Type your messages and press Enter")
        print("[+] Type 'exit' to end session")
        print("="*60 + "\n")
        
        self.chat_active = True
        
        # Thread to receive messages
        def receive_messages():
            """Thread to receive and decrypt messages from server"""
            while self.chat_active:
                try:
                    # Use select with timeout to allow clean shutdown
                    ready = select.select([self.socket], [], [], 0.5)
                    if ready[0]:
                        data = self.receive_message()
                        
                        if not data:
                            print("\n[!] Server disconnected")
                            self.chat_active = False
                            break
                        
                        if data.get('type') == 'msg':
                            if not self.handle_incoming_message(data):
                                print("[!] Failed to process message")
                        
                        elif data.get('type') == 'exit':
                            print(f"\n[+] Server has ended the session")
                            self.chat_active = False
                            break
                
                except Exception as e:
                    if self.chat_active:
                        print(f"\n[!] Error receiving message: {e}")
                        self.chat_active = False
                    break
        
        # Start receive thread
        receive_thread = threading.Thread(target=receive_messages, daemon=True)
        receive_thread.start()
        
        # Send messages
        try:
            while self.chat_active:
                # Check for user input with timeout
                if sys.stdin in select.select([sys.stdin], [], [], 0.5)[0]:
                    message = sys.stdin.readline().strip()
                    
                    if message.lower() == 'exit':
                        print("[+] Ending chat session...")
                        self.chat_active = False
                        # Send exit notification
                        exit_msg = {'type': 'exit', 'message': 'Client ended session'}
                        self.send_message(exit_msg)
                        break
                    
                    if message:
                        self.send_chat_message(message)
        
        except KeyboardInterrupt:
            print("\n[!] Chat interrupted")
            self.chat_active = False
        
        finally:
            self.chat_active = False
            receive_thread.join(timeout=2)
    
    def handle_incoming_message(self, data):
        """Handle incoming encrypted message from server"""
        try:
            seqno = data.get('seqno')
            timestamp = data.get('ts')
            ciphertext = data.get('ct')
            signature = data.get('sig')
            
            # Validate sequence number (replay protection)
            if seqno <= self.server_sequence_number:
                print(f"\n[!] REPLAY ATTACK DETECTED: seqno {seqno} <= {self.server_sequence_number}")
                return False
            
            self.server_sequence_number = seqno
            
            # Verify signature
            msg_data = f"{seqno}||{timestamp}||{ciphertext}".encode('utf-8')
            server_public_key = self.server_cert.public_key()
            
            if not CryptoUtils.verify_signature(server_public_key, msg_data, signature):
                print("\n[!] SIG_FAIL: Message signature verification failed")
                return False
            
            # Decrypt message
            decrypted = CryptoUtils.aes_decrypt(
                self.session_key,
                data.get('iv'),
                ciphertext
            )
            plaintext = decrypted.decode('utf-8')
            
            # Log to transcript
            self.log_to_transcript('server', seqno, timestamp, ciphertext, signature)
            
            # Display message
            print(f"\nServer: {plaintext}")
            print(f"{self.username}: ", end='', flush=True)
            
            return True
        
        except Exception as e:
            print(f"\n[!] Error processing incoming message: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_chat_message(self, plaintext):
        """Send encrypted chat message to server"""
        try:
            self.sequence_number += 1
            timestamp = int(time.time() * 1000)
            
            # Encrypt message
            encrypted = CryptoUtils.aes_encrypt(self.session_key, plaintext)
            
            # Create signature over seqno || timestamp || ciphertext
            msg_data = f"{self.sequence_number}||{timestamp}||{encrypted['ciphertext']}".encode('utf-8')
            signature = CryptoUtils.sign_data(self.client_key, msg_data)
            
            # Build message
            message = {
                'type': 'msg',
                'seqno': self.sequence_number,
                'ts': timestamp,
                'iv': encrypted['iv'],
                'ct': encrypted['ciphertext'],
                'sig': signature
            }
            
            self.send_message(message)
            
            # Log to transcript
            self.log_to_transcript('client', self.sequence_number, timestamp,
                                 encrypted['ciphertext'], signature)
            
            print(f"{self.username}: ", end='', flush=True)
        
        except Exception as e:
            print(f"\n[!] Error sending message: {e}")
    
    # ========== PHASE 5: SESSION CLOSURE ==========
    
    def handle_session_closure(self):
        """Handle session closure and generate non-repudiation receipt"""
        print("\n" + "="*60)
        print("PHASE 5: SESSION CLOSURE & NON-REPUDIATION")
        print("="*60)
        
        try:
            if not self.transcript:
                print("[!] No messages in transcript")
                return
            
            # Compute transcript hash
            transcript_content = '\n'.join(self.transcript)
            transcript_hash = CryptoUtils.compute_sha256_hex(transcript_content)
            
            print(f"[+] Transcript hash computed: {transcript_hash[:32]}...")
            
            # Create and sign receipt
            receipt = {
                'type': 'receipt',
                'peer': 'client',
                'first_seq': 1,
                'last_seq': self.sequence_number,
                'transcript_sha256': transcript_hash,
                'sig': CryptoUtils.sign_data(self.client_key, transcript_hash.encode('utf-8'))
            }
            
            # Save receipt
            os.makedirs('transcripts', exist_ok=True)
            receipt_file = f"transcripts/receipt_client_{int(time.time())}.json"
            with open(receipt_file, 'w') as f:
                json.dump(receipt, f, indent=2)
            
            print(f"[✓] Session receipt saved: {receipt_file}")
            
            # Close transcript file
            if self.transcript_file:
                self.transcript_file.close()
                print(f"[✓] Transcript saved: {self.transcript_file.name}")
        
        except Exception as e:
            print(f"[!] Error during session closure: {e}")
    
    # ========== UTILITY FUNCTIONS ==========
    
    def init_transcript(self):
        """Initialize transcript file"""
        os.makedirs('transcripts', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"transcripts/client_transcript_{timestamp}.txt"
        self.transcript_file = open(filename, 'w')
        self.transcript_file.write(f"# SecureChat Transcript - Client\n")
        self.transcript_file.write(f"# Session started: {datetime.now().isoformat()}\n")
        self.transcript_file.write(f"# User: {self.username}\n")
        self.transcript_file.write(f"# Server cert fingerprint: {CryptoUtils.get_certificate_fingerprint(self.server_cert)}\n")
        self.transcript_file.write(f"#\n")
        self.transcript_file.write(f"# Format: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint\n")
        self.transcript_file.write(f"#\n\n")
        print(f"[+] Transcript file created: {filename}")
    
    def log_to_transcript(self, sender, seqno, timestamp, ciphertext, signature):
        """Log message to transcript"""
        cert = self.client_cert if sender == 'client' else self.server_cert
        fingerprint = CryptoUtils.get_certificate_fingerprint(cert)
        
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{fingerprint}"
        self.transcript.append(line)
        
        if self.transcript_file:
            self.transcript_file.write(line + '\n')
            self.transcript_file.flush()
    
    def send_message(self, message):
        """Send JSON message to server"""
        data = json.dumps(message).encode('utf-8')
        length = len(data)
        self.socket.sendall(length.to_bytes(4, 'big') + data)
    
    def receive_message(self):
        """Receive JSON message from server"""
        try:
            # Receive length (4 bytes)
            length_bytes = self.receive_exact(4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive data
            data = self.receive_exact(length)
            if not data:
                return None
            
            return json.loads(data.decode('utf-8'))
        
        except Exception as e:
            if self.chat_active:
                print(f"[!] Error receiving message: {e}")
            return None
    
    def receive_exact(self, num_bytes):
        """Receive exactly num_bytes from socket"""
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        if self.transcript_file:
            try:
                self.transcript_file.close()
            except:
                pass
        
        print("\n[+] Client stopped")

# ========== MAIN ==========

def main():
    print("="*60)
    print("SecureChat Client")
    print("="*60)
    
    try:
        client = SecureChatClient()
        client.start()
    except KeyboardInterrupt:
        print("\n[!] Client stopped by user")
    except Exception as e:
        print(f"[!] Client error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
