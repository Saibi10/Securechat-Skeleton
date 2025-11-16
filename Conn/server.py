#!/usr/bin/env python3
"""
SecureChat Server
Handles client connections, authentication, and encrypted messaging.
"""

import socket
import json
import os
import sys
import time
from datetime import datetime
from dotenv import load_dotenv
from crypto_utils import CryptoUtils, hash_password, verify_password
from db_utils import DatabaseManager
from cryptography import x509

# Load environment variables
load_dotenv()

class SecureChatServer:
    """Secure Chat Server"""
    
    def __init__(self):
        """Initialize server"""
        self.host = os.getenv('SERVER_HOST', 'localhost')
        self.port = int(os.getenv('SERVER_PORT', 5555))
        
        # Load certificates
        print("[+] Loading server certificates...")
        self.ca_cert = CryptoUtils.load_certificate(os.getenv('CA_CERT_PATH', 'certs/ca.crt'))
        self.server_cert = CryptoUtils.load_certificate(os.getenv('SERVER_CERT_PATH', 'certs/server.crt'))
        self.server_key = CryptoUtils.load_private_key(os.getenv('SERVER_KEY_PATH', 'certs/server.key'))
        
        # Database
        self.db = DatabaseManager()
        
        # Session state
        self.session_key = None
        self.client_cert = None
        self.authenticated_user = None
        self.sequence_number = 0
        self.client_sequence_number = 0
        
        # Transcript
        self.transcript = []
        self.transcript_file = None
        
        # DH state
        self.dh_params = None
        
        print("[+] Server initialized successfully")
    
    def start(self):
        """Start server and listen for connections"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            print(f"\n[+] Server listening on {self.host}:{self.port}")
            print("[+] Waiting for client connection...\n")
            
            while True:
                client_socket, address = server_socket.accept()
                print(f"[+] Connection from {address}")
                
                try:
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"[!] Error handling client: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    client_socket.close()
                    print("\n[+] Client disconnected")
                    print("[+] Ready for new client connection...\n")
                    
                    # Reset session state
                    self.reset_session()
        
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        finally:
            server_socket.close()
            self.db.close()
    
    def reset_session(self):
        """Reset session state for new client"""
        self.session_key = None
        self.client_cert = None
        self.authenticated_user = None
        self.sequence_number = 0
        self.client_sequence_number = 0
        self.transcript = []
        self.transcript_file = None
        self.dh_params = None
    
    def handle_client(self, client_socket):
        """Handle client connection through full protocol"""
        
        # Phase 1: Certificate Exchange & Validation
        if not self.handle_certificate_exchange(client_socket):
            return
        
        # Phase 2: Authentication (Register/Login)
        if not self.handle_authentication(client_socket):
            return
        
        # Phase 3: Key Agreement (DH)
        if not self.handle_key_agreement(client_socket):
            return
        
        # Phase 4: Chat Loop
        self.handle_chat_session(client_socket)
        
        # Phase 5: Session Closure & Non-Repudiation
        self.handle_session_closure(client_socket)
    
    # ========== PHASE 1: CERTIFICATE EXCHANGE & VALIDATION ==========
    
    def handle_certificate_exchange(self, client_socket):
        """Handle certificate exchange and validation"""
        print("\n" + "="*60)
        print("PHASE 1: CERTIFICATE EXCHANGE & VALIDATION")
        print("="*60)
        
        try:
            # Wait for client hello
            data = self.receive_message(client_socket)
            if not data or data.get('type') != 'hello':
                print("[!] Expected 'hello' message")
                return False
            
            print("[+] Received client hello")
            
            # Extract and validate client certificate
            client_cert_pem = data.get('client_cert')
            if not client_cert_pem:
                self.send_error(client_socket, "Missing client certificate")
                return False
            
            # Parse certificate
            try:
                self.client_cert = CryptoUtils.pem_to_certificate(client_cert_pem)
                print(f"[+] Client certificate received (CN: {self.client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value})")
            except Exception as e:
                print(f"[!] Failed to parse client certificate: {e}")
                self.send_error(client_socket, "BAD_CERT: Invalid certificate format")
                return False
            
            # Validate client certificate
            is_valid, error_msg = CryptoUtils.validate_certificate(self.client_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] Client certificate validation failed: {error_msg}")
                self.send_error(client_socket, f"BAD_CERT: {error_msg}")
                return False
            
            print("[✓] Client certificate validated successfully")
            
            # Send server hello with certificate
            server_hello = {
                'type': 'server_hello',
                'server_cert': CryptoUtils.certificate_to_pem(self.server_cert),
                'nonce': CryptoUtils.generate_random_bytes(16).hex()
            }
            self.send_message(client_socket, server_hello)
            print("[+] Sent server hello with certificate")
            
            return True
        
        except Exception as e:
            print(f"[!] Certificate exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ========== PHASE 2: AUTHENTICATION ==========
    
    def handle_authentication(self, client_socket):
        """Handle user registration or login"""
        print("\n" + "="*60)
        print("PHASE 2: AUTHENTICATION (REGISTER/LOGIN)")
        print("="*60)
        
        try:
            # Generate temporary DH for credential encryption
            print("[+] Generating temporary DH parameters for credential exchange...")
            temp_dh = CryptoUtils.generate_dh_parameters()
            
            # Send DH parameters
            dh_init = {
                'type': 'dh_init',
                'p': temp_dh['p'],
                'g': temp_dh['g'],
                'B': temp_dh['public']
            }
            self.send_message(client_socket, dh_init)
            print("[+] Sent temporary DH parameters")
            
            # Receive client's DH public key
            data = self.receive_message(client_socket)
            if not data or 'A' not in data:
                print("[!] Invalid DH response from client")
                return False
            
            client_public = data['A']
            print("[+] Received client DH public key")
            
            # Compute shared secret and derive AES key
            shared_secret = CryptoUtils.compute_dh_shared_secret(
                temp_dh['private'],
                client_public,
                temp_dh['p']
            )
            temp_aes_key = CryptoUtils.derive_aes_key_from_dh(shared_secret)
            print("[+] Temporary AES key derived for credential protection")
            
            # Receive encrypted authentication request
            data = self.receive_message(client_socket)
            if not data or data.get('type') not in ['register', 'login']:
                print("[!] Invalid authentication request")
                return False
            
            auth_type = data['type']
            print(f"[+] Received {auth_type} request (encrypted)")
            
            # Decrypt credentials
            try:
                encrypted_data = data.get('encrypted_data')
                if not encrypted_data:
                    raise ValueError("Missing encrypted data")
                
                decrypted = CryptoUtils.aes_decrypt(
                    temp_aes_key,
                    encrypted_data['iv'],
                    encrypted_data['ciphertext']
                )
                credentials = json.loads(decrypted.decode('utf-8'))
                print("[+] Credentials decrypted successfully")
            
            except Exception as e:
                print(f"[!] Failed to decrypt credentials: {e}")
                self.send_error(client_socket, "Decryption failed")
                return False
            
            # Handle registration or login
            if auth_type == 'register':
                success = self.handle_registration(client_socket, credentials, temp_aes_key)
            else:  # login
                success = self.handle_login(client_socket, credentials, temp_aes_key)
            
            return success
        
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_registration(self, client_socket, credentials, aes_key):
        """Handle user registration"""
        try:
            email = credentials.get('email')
            username = credentials.get('username')
            password = credentials.get('password')
            
            if not all([email, username, password]):
                self.send_encrypted_response(client_socket, aes_key, {
                    'type': 'auth_response',
                    'success': False,
                    'message': 'Missing required fields'
                })
                return False
            
            print(f"[+] Processing registration for: {email}")
            
            # Register user in database
            success, message = self.db.register_user(email, username, password)
            
            response = {
                'type': 'auth_response',
                'success': success,
                'message': message
            }
            
            self.send_encrypted_response(client_socket, aes_key, response)
            
            if success:
                print(f"[✓] User registered successfully: {username}")
                self.authenticated_user = username
                return True
            else:
                print(f"[!] Registration failed: {message}")
                return False
        
        except Exception as e:
            print(f"[!] Registration error: {e}")
            self.send_encrypted_response(client_socket, aes_key, {
                'type': 'auth_response',
                'success': False,
                'message': f'Registration error: {str(e)}'
            })
            return False
    
    def handle_login(self, client_socket, credentials, aes_key):
        """Handle user login"""
        try:
            email = credentials.get('email')
            password = credentials.get('password')
            
            if not all([email, password]):
                self.send_encrypted_response(client_socket, aes_key, {
                    'type': 'auth_response',
                    'success': False,
                    'message': 'Missing email or password'
                })
                return False
            
            print(f"[+] Processing login for: {email}")
            
            # Authenticate user
            success, result = self.db.authenticate_user(email, password)
            
            if success:
                username = result
                response = {
                    'type': 'auth_response',
                    'success': True,
                    'message': f'Welcome back, {username}!',
                    'username': username
                }
                self.authenticated_user = username
                print(f"[✓] User authenticated: {username}")
            else:
                response = {
                    'type': 'auth_response',
                    'success': False,
                    'message': result
                }
                print(f"[!] Authentication failed: {result}")
            
            self.send_encrypted_response(client_socket, aes_key, response)
            return success
        
        except Exception as e:
            print(f"[!] Login error: {e}")
            self.send_encrypted_response(client_socket, aes_key, {
                'type': 'auth_response',
                'success': False,
                'message': f'Login error: {str(e)}'
            })
            return False
    
    # ========== PHASE 3: KEY AGREEMENT ==========
    
    def handle_key_agreement(self, client_socket):
        """Handle Diffie-Hellman key exchange for chat session"""
        print("\n" + "="*60)
        print("PHASE 3: KEY AGREEMENT (DIFFIE-HELLMAN)")
        print("="*60)
        
        try:
            # Receive client's DH parameters
            data = self.receive_message(client_socket)
            if not data or data.get('type') != 'dh_client':
                print("[!] Invalid DH client message")
                return False
            
            p = data['p']
            g = data['g']
            client_A = data['A']
            
            print("[+] Received client DH parameters")
            print(f"    p: {str(p)[:50]}... ({p.bit_length()} bits)")
            print(f"    g: {g}")
            print(f"    A: {str(client_A)[:50]}...")
            
            # Generate server's DH keys using same p and g
            import secrets
            server_private = int.from_bytes(secrets.token_bytes(256), 'big') % (p - 2) + 2
            server_B = pow(g, server_private, p)
            
            print("[+] Generated server DH keys")
            
            # Send server's public key
            dh_response = {
                'type': 'dh_server',
                'B': server_B
            }
            self.send_message(client_socket, dh_response)
            print("[+] Sent server DH public key")
            
            # Compute shared secret
            shared_secret = CryptoUtils.compute_dh_shared_secret(server_private, client_A, p)
            
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
    
    def handle_chat_session(self, client_socket):
        """Handle encrypted chat messages"""
        print("\n" + "="*60)
        print("PHASE 4: ENCRYPTED CHAT SESSION")
        print("="*60)
        print(f"[+] Chat session started with user: {self.authenticated_user}")
        print("[+] Type 'exit' to end session")
        print("="*60 + "\n")
        
        # Send ready signal
        ready_msg = {
            'type': 'chat_ready',
            'message': 'Chat session initialized. Start messaging!'
        }
        self.send_encrypted_message(client_socket, json.dumps(ready_msg))
        
        import threading
        import select
        
        # Flag to control threads
        self.chat_active = True
        
        def receive_messages():
            """Thread to receive messages from client"""
            while self.chat_active:
                try:
                    # Check if data is available
                    ready = select.select([client_socket], [], [], 0.5)
                    if ready[0]:
                        data = self.receive_message(client_socket)
                        
                        if not data:
                            print("\n[!] Client disconnected")
                            self.chat_active = False
                            break
                        
                        if data.get('type') == 'msg':
                            if not self.handle_incoming_message(data):
                                print("[!] Failed to process message")
                        
                        elif data.get('type') == 'exit':
                            print(f"\n[+] {self.authenticated_user} has left the chat")
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
                # Use select to check for input with timeout
                import sys
                if sys.stdin in select.select([sys.stdin], [], [], 0.5)[0]:
                    message = sys.stdin.readline().strip()
                    
                    if message.lower() == 'exit':
                        print("[+] Ending chat session...")
                        self.chat_active = False
                        # Send exit notification
                        exit_msg = {'type': 'exit', 'message': 'Server ended session'}
                        self.send_message(client_socket, exit_msg)
                        break
                    
                    if message:
                        self.send_chat_message(client_socket, message)
        
        except KeyboardInterrupt:
            print("\n[!] Chat interrupted")
            self.chat_active = False
        
        finally:
            self.chat_active = False
            receive_thread.join(timeout=2)
    
    def handle_incoming_message(self, data):
        """Handle incoming encrypted message from client"""
        try:
            seqno = data.get('seqno')
            timestamp = data.get('ts')
            ciphertext = data.get('ct')
            signature = data.get('sig')
            
            # Validate sequence number (replay protection)
            if seqno <= self.client_sequence_number:
                print(f"[!] REPLAY ATTACK DETECTED: seqno {seqno} <= {self.client_sequence_number}")
                return False
            
            self.client_sequence_number = seqno
            
            # Verify signature
            msg_data = f"{seqno}||{timestamp}||{ciphertext}".encode('utf-8')
            client_public_key = self.client_cert.public_key()
            
            if not CryptoUtils.verify_signature(client_public_key, msg_data, signature):
                print("[!] SIG_FAIL: Message signature verification failed")
                return False
            
            # Decrypt message
            decrypted = CryptoUtils.aes_decrypt(
                self.session_key,
                data.get('iv'),
                ciphertext
            )
            plaintext = decrypted.decode('utf-8')
            
            # Log to transcript
            self.log_to_transcript('client', seqno, timestamp, ciphertext, signature)
            
            # Display message
            print(f"\n{self.authenticated_user}: {plaintext}")
            print("You: ", end='', flush=True)
            
            return True
        
        except Exception as e:
            print(f"[!] Error processing incoming message: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_chat_message(self, client_socket, plaintext):
        """Send encrypted chat message to client"""
        try:
            self.sequence_number += 1
            self.send_encrypted_message(client_socket, plaintext)
            print("You: ", end='', flush=True)
        except Exception as e:
            print(f"[!] Error sending message: {e}")
    
    def send_encrypted_message(self, client_socket, plaintext):
        """Encrypt and send message with signature"""
        try:
            # Increment sequence number
            timestamp = int(time.time() * 1000)  # milliseconds
            
            # Encrypt message
            encrypted = CryptoUtils.aes_encrypt(self.session_key, plaintext)
            
            # Create signature over seqno || timestamp || ciphertext
            msg_data = f"{self.sequence_number}||{timestamp}||{encrypted['ciphertext']}".encode('utf-8')
            signature = CryptoUtils.sign_data(self.server_key, msg_data)
            
            # Build message
            message = {
                'type': 'msg',
                'seqno': self.sequence_number,
                'ts': timestamp,
                'iv': encrypted['iv'],
                'ct': encrypted['ciphertext'],
                'sig': signature
            }
            
            self.send_message(client_socket, message)
            
            # Log to transcript
            self.log_to_transcript('server', self.sequence_number, timestamp, 
                                 encrypted['ciphertext'], signature)
        
        except Exception as e:
            print(f"[!] Error sending encrypted message: {e}")
            raise
    
    # ========== PHASE 5: SESSION CLOSURE ==========
    
    def handle_session_closure(self, client_socket):
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
                'peer': 'server',
                'first_seq': 1,
                'last_seq': self.sequence_number,
                'transcript_sha256': transcript_hash,
                'sig': CryptoUtils.sign_data(self.server_key, transcript_hash.encode('utf-8'))
            }
            
            # Save receipt
            receipt_file = f"transcripts/receipt_server_{int(time.time())}.json"
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
        filename = f"transcripts/server_transcript_{timestamp}.txt"
        self.transcript_file = open(filename, 'w')
        self.transcript_file.write(f"# SecureChat Transcript - Server\n")
        self.transcript_file.write(f"# Session started: {datetime.now().isoformat()}\n")
        self.transcript_file.write(f"# User: {self.authenticated_user}\n")
        self.transcript_file.write(f"# Client cert fingerprint: {CryptoUtils.get_certificate_fingerprint(self.client_cert)}\n")
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
    
    def send_message(self, client_socket, message):
        """Send JSON message to client"""
        data = json.dumps(message).encode('utf-8')
        length = len(data)
        client_socket.sendall(length.to_bytes(4, 'big') + data)
    
    def receive_message(self, client_socket):
        """Receive JSON message from client"""
        try:
            # Receive length (4 bytes)
            length_bytes = self.receive_exact(client_socket, 4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive data
            data = self.receive_exact(client_socket, length)
            if not data:
                return None
            
            return json.loads(data.decode('utf-8'))
        
        except Exception as e:
            print(f"[!] Error receiving message: {e}")
            return None
    
    def receive_exact(self, client_socket, num_bytes):
        """Receive exactly num_bytes from socket"""
        data = b''
        while len(data) < num_bytes:
            chunk = client_socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def send_error(self, client_socket, error_message):
        """Send error message to client"""
        error = {
            'type': 'error',
            'message': error_message
        }
        self.send_message(client_socket, error)
    
    def send_encrypted_response(self, client_socket, aes_key, response):
        """Send encrypted response"""
        encrypted = CryptoUtils.aes_encrypt(aes_key, json.dumps(response))
        message = {
            'type': 'encrypted_response',
            'encrypted_data': encrypted
        }
        self.send_message(client_socket, message)

# ========== MAIN ==========

def main():
    print("="*60)
    print("SecureChat Server")
    print("="*60)
    
    # Import for certificate validation
    from cryptography import x509
    
    try:
        server = SecureChatServer()
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
    except Exception as e:
        print(f"[!] Server error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
