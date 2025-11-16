#!/usr/bin/env python3
"""
Generate Root Certificate Authority (CA)
This creates a self-signed CA certificate used to sign client/server certificates.
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_ca():
    """Generate a self-signed root CA certificate"""
    
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    # Generate private key
    print("[+] Generating CA private key (4096-bit RSA)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Define CA subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    # Build certificate
    print("[+] Building CA certificate...")
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
    
    # Add extensions
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    cert_builder = cert_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    
    # Self-sign the certificate
    certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    print("[+] Saving CA private key to certs/ca.key...")
    with open("certs/ca.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    print("[+] Saving CA certificate to certs/ca.crt...")
    with open("certs/ca.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print("[✓] CA generation complete!")
    print(f"    CA Certificate: certs/ca.crt")
    print(f"    CA Private Key: certs/ca.key")
    print("\n[!] IMPORTANT: Keep ca.key secure and NEVER commit it to Git!")
    
    return private_key, certificate

if __name__ == "__main__":
    print("=" * 60)
    print("SecureChat Certificate Authority Generator")
    print("=" * 60)
    generate_ca()
