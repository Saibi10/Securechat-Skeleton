#!/usr/bin/env python3
"""
Cryptographic Utilities for SecureChat
Provides functions for encryption, signatures, key derivation, and certificate handling.
"""

import os
import hashlib
import base64
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from datetime import datetime

class CryptoUtils:
    """Cryptographic utility functions"""
    
    @staticmethod
    def generate_random_bytes(length=16):
        """Generate cryptographically secure random bytes"""
        return os.urandom(length)
    
    @staticmethod
    def compute_sha256(data):
        """Compute SHA-256 hash of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def compute_sha256_hex(data):
        """Compute SHA-256 hash and return as hex string"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    # ============ PKCS#7 Padding ============
    
    @staticmethod
    def pkcs7_pad(data, block_size=16):
        """
        Apply PKCS#7 padding to data
        
        Args:
            data: bytes to pad
            block_size: block size in bytes (16 for AES-128)
        
        Returns:
            Padded data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def pkcs7_unpad(data):
        """
        Remove PKCS#7 padding from data
        
        Args:
            data: padded bytes
        
        Returns:
            Unpadded data
        """
        padding_length = data[-1]
        
        # Validate padding
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid PKCS#7 padding")
        
        for i in range(padding_length):
            if data[-(i+1)] != padding_length:
                raise ValueError("Invalid PKCS#7 padding")
        
        return data[:-padding_length]
    
    # ============ AES-128 Encryption (Block Cipher) ============
    
    @staticmethod
    def aes_encrypt(key, plaintext):
        """
        Encrypt data using AES-128 in CBC mode with PKCS#7 padding
        
        Args:
            key: 16-byte AES key
            plaintext: data to encrypt
        
        Returns:
            dict with 'iv' and 'ciphertext' (both base64-encoded)
        """
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        
        # Generate random IV
        iv = CryptoUtils.generate_random_bytes(16)
        
        # Pad plaintext
        padded_plaintext = CryptoUtils.pkcs7_pad(plaintext)
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    @staticmethod
    def aes_decrypt(key, iv_b64, ciphertext_b64):
        """
        Decrypt data using AES-128 in CBC mode
        
        Args:
            key: 16-byte AES key
            iv_b64: base64-encoded IV
            ciphertext_b64: base64-encoded ciphertext
        
        Returns:
            Decrypted plaintext (bytes)
        """
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        
        # Decode from base64
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = CryptoUtils.pkcs7_unpad(padded_plaintext)
        
        return plaintext
    
    # ============ Diffie-Hellman ============
    
    @staticmethod
    def generate_dh_parameters():
        """
        Generate Diffie-Hellman parameters
        Using a 2048-bit safe prime
        
        Returns:
            dict with 'p' (prime), 'g' (generator), 'private' (private key), 'public' (public key)
        """
        # Use well-known 2048-bit MODP Group (RFC 3526)
        p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )
        g = 2
        
        # Generate private key (random number between 2 and p-2)
        private_key = int.from_bytes(CryptoUtils.generate_random_bytes(256), 'big') % (p - 2) + 2
        
        # Compute public key: g^private mod p
        public_key = pow(g, private_key, p)
        
        return {
            'p': p,
            'g': g,
            'private': private_key,
            'public': public_key
        }
    
    @staticmethod
    def compute_dh_shared_secret(private_key, other_public_key, p):
        """
        Compute DH shared secret
        
        Args:
            private_key: own private key
            other_public_key: other party's public key
            p: prime modulus
        
        Returns:
            Shared secret (integer)
        """
        return pow(other_public_key, private_key, p)
    
    @staticmethod
    def derive_aes_key_from_dh(shared_secret):
        """
        Derive AES-128 key from DH shared secret
        K = Trunc16(SHA256(big-endian(Ks)))
        
        Args:
            shared_secret: DH shared secret (integer)
        
        Returns:
            16-byte AES key
        """
        # Convert shared secret to big-endian bytes
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        
        # Hash with SHA-256
        hash_digest = CryptoUtils.compute_sha256(secret_bytes)
        
        # Truncate to 16 bytes
        aes_key = hash_digest[:16]
        
        return aes_key
    
    # ============ RSA Signatures ============
    
    @staticmethod
    def load_private_key(path):
        """Load RSA private key from PEM file"""
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    
    @staticmethod
    def load_certificate(path):
        """Load X.509 certificate from PEM file"""
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    
    @staticmethod
    def sign_data(private_key, data):
        """
        Sign data using RSA private key with SHA-256
        
        Args:
            private_key: RSA private key
            data: data to sign (bytes)
        
        Returns:
            base64-encoded signature
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        signature = private_key.sign(
            data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(public_key, data, signature_b64):
        """
        Verify RSA signature
        
        Args:
            public_key: RSA public key
            data: original data (bytes)
            signature_b64: base64-encoded signature
        
        Returns:
            True if valid, False otherwise
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                data,
                rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    # ============ Certificate Validation ============
    
    @staticmethod
    def validate_certificate(cert, ca_cert):
        """
        Validate certificate against CA
        
        Args:
            cert: Certificate to validate
            ca_cert: CA certificate
        
        Returns:
            tuple (is_valid, error_message)
        """
        try:
            # Check expiration
            now = datetime.utcnow()
            if cert.not_valid_before > now:
                return False, "Certificate not yet valid"
            if cert.not_valid_after < now:
                return False, "Certificate has expired"
            
            # Verify signature from CA
            ca_public_key = ca_cert.public_key()
            try:
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    rsa_padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            except Exception as e:
                return False, f"Certificate signature verification failed: {str(e)}"
            
            # Check issuer matches CA subject
            if cert.issuer != ca_cert.subject:
                return False, "Certificate issuer does not match CA subject"
            
            return True, None
            
        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"
    
    @staticmethod
    def get_certificate_fingerprint(cert):
        """Get SHA-256 fingerprint of certificate"""
        fingerprint = cert.fingerprint(hashes.SHA256())
        return fingerprint.hex()
    
    @staticmethod
    def certificate_to_pem(cert):
        """Convert certificate to PEM string"""
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    @staticmethod
    def pem_to_certificate(pem_str):
        """Convert PEM string to certificate"""
        return x509.load_pem_x509_certificate(
            pem_str.encode('utf-8'),
            default_backend()
        )

# ============ Password Hashing ============

def hash_password(password, salt=None):
    """
    Hash password with salt using SHA-256
    
    Args:
        password: plaintext password
        salt: 16-byte salt (generated if None)
    
    Returns:
        dict with 'salt' (base64) and 'hash' (hex)
    """
    if salt is None:
        salt = CryptoUtils.generate_random_bytes(16)
    elif isinstance(salt, str):
        salt = base64.b64decode(salt)
    
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Compute hash: SHA256(salt || password)
    pwd_hash = hashlib.sha256(salt + password).hexdigest()
    
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'hash': pwd_hash
    }

def verify_password(password, salt_b64, stored_hash):
    """
    Verify password against stored hash
    
    Args:
        password: plaintext password
        salt_b64: base64-encoded salt
        stored_hash: hex-encoded hash
    
    Returns:
        True if password matches, False otherwise
    """
    result = hash_password(password, salt_b64)
    return result['hash'] == stored_hash
