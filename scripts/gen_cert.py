#!/usr/bin/env python3
"""
Generate Server and Client Certificates
These certificates are signed by the CA and used for mutual authentication.
"""

import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_ca():
    """Load CA certificate and private key"""
    print("[+] Loading CA certificate and key...")
    
    # Load CA certificate
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Load CA private key
    with open("certs/ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key

def generate_certificate(cert_type, common_name, ca_cert, ca_key):
    """
    Generate a certificate signed by the CA
    
    Args:
        cert_type: 'server' or 'client'
        common_name: CN for the certificate
        ca_cert: CA certificate
        ca_key: CA private key
    """
    
    print(f"\n[+] Generating {cert_type} private key (2048-bit RSA)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Define subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"SecureChat {cert_type.title()}"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print(f"[+] Building {cert_type} certificate...")
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 year
    
    # Add extensions
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    if cert_type == "server":
        # Server certificate extensions
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:  # client
        # Client certificate extensions
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
    
    cert_builder = cert_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    cert_builder = cert_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )
    
    # Sign with CA
    certificate = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_path = f"certs/{cert_type}.key"
    cert_path = f"certs/{cert_type}.crt"
    
    print(f"[+] Saving {cert_type} private key to {key_path}...")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    print(f"[+] Saving {cert_type} certificate to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"[✓] {cert_type.title()} certificate generated successfully!")
    
    return private_key, certificate

def main():
    print("=" * 60)
    print("SecureChat Certificate Generator")
    print("=" * 60)
    
    # Check if CA exists
    if not os.path.exists("certs/ca.crt") or not os.path.exists("certs/ca.key"):
        print("[!] ERROR: CA certificate not found!")
        print("    Run 'python scripts/gen_ca.py' first to create the CA.")
        sys.exit(1)
    
    # Load CA
    ca_cert, ca_key = load_ca()
    
    # Generate server certificate
    print("\n" + "=" * 60)
    print("Generating Server Certificate")
    print("=" * 60)
    generate_certificate("server", "securechat-server", ca_cert, ca_key)
    
    # Generate client certificate
    print("\n" + "=" * 60)
    print("Generating Client Certificate")
    print("=" * 60)
    generate_certificate("client", "securechat-client", ca_cert, ca_key)
    
    print("\n" + "=" * 60)
    print("[✓] All certificates generated successfully!")
    print("=" * 60)
    print("\nGenerated files:")
    print("  - certs/server.crt (Server Certificate)")
    print("  - certs/server.key (Server Private Key)")
    print("  - certs/client.crt (Client Certificate)")
    print("  - certs/client.key (Client Private Key)")
    print("\n[!] IMPORTANT: Keep all .key files secure and NEVER commit them to Git!")

if __name__ == "__main__":
    import ipaddress
    main()
