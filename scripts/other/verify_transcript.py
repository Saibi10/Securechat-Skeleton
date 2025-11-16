#!/usr/bin/env python3
"""
Transcript and Receipt Verification Tool
Verifies the integrity and authenticity of chat transcripts and receipts.
"""

import json
import sys
from crypto_utils import CryptoUtils

def verify_transcript(transcript_file, receipt_file, cert_file):
    """
    Verify transcript integrity using receipt
    
    Args:
        transcript_file: Path to transcript file
        receipt_file: Path to receipt JSON file
        cert_file: Path to signer's certificate
    """
    print("="*60)
    print("Transcript & Receipt Verification")
    print("="*60)
    
    try:
        # Load transcript
        print(f"\n[+] Loading transcript: {transcript_file}")
        with open(transcript_file, 'r') as f:
            lines = f.readlines()
        
        # Extract transcript data (skip comments)
        transcript_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        transcript_content = '\n'.join(transcript_lines)
        
        print(f"    Lines: {len(transcript_lines)}")
        
        # Compute transcript hash
        computed_hash = CryptoUtils.compute_sha256_hex(transcript_content)
        print(f"[+] Computed transcript hash: {computed_hash[:32]}...")
        
        # Load receipt
        print(f"\n[+] Loading receipt: {receipt_file}")
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
        
        print(f"    Peer: {receipt.get('peer')}")
        print(f"    First seq: {receipt.get('first_seq')}")
        print(f"    Last seq: {receipt.get('last_seq')}")
        
        receipt_hash = receipt.get('transcript_sha256')
        print(f"    Receipt hash: {receipt_hash[:32]}...")
        
        # Compare hashes
        if computed_hash != receipt_hash:
            print("\n[✗] VERIFICATION FAILED!")
            print("    Transcript hash does not match receipt")
            print("    The transcript may have been tampered with!")
            return False
        
        print("\n[✓] Transcript hash matches receipt")
        
        # Load certificate
        print(f"\n[+] Loading certificate: {cert_file}")
        cert = CryptoUtils.load_certificate(cert_file)
        
        cn = cert.subject.get_attributes_for_oid(CryptoUtils.x509.NameOID.COMMON_NAME)[0].value
        print(f"    Certificate CN: {cn}")
        print(f"    Fingerprint: {CryptoUtils.get_certificate_fingerprint(cert)[:32]}...")
        
        # Verify signature
        print(f"\n[+] Verifying receipt signature...")
        public_key = cert.public_key()
        signature = receipt.get('sig')
        
        if CryptoUtils.verify_signature(public_key, receipt_hash.encode('utf-8'), signature):
            print("[✓] Receipt signature is VALID")
            print("\n" + "="*60)
            print("VERIFICATION SUCCESSFUL!")
            print("="*60)
            print("\nThe transcript is authentic and has not been tampered with.")
            print(f"Signed by: {cn}")
            return True
        else:
            print("[✗] Receipt signature is INVALID")
            print("\n" + "="*60)
            print("VERIFICATION FAILED!")
            print("="*60)
            print("\nThe receipt signature could not be verified.")
            print("This may indicate tampering or forgery!")
            return False
    
    except Exception as e:
        print(f"\n[!] Verification error: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_message(transcript_file, message_line_num, signer_cert):
    """
    Verify individual message signature
    
    Args:
        transcript_file: Path to transcript file
        message_line_num: Line number of message to verify (1-indexed)
        signer_cert: Path to signer's certificate
    """
    print("="*60)
    print("Individual Message Verification")
    print("="*60)
    
    try:
        # Load transcript
        print(f"\n[+] Loading transcript: {transcript_file}")
        with open(transcript_file, 'r') as f:
            lines = f.readlines()
        
        # Extract transcript data (skip comments)
        transcript_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        
        if message_line_num < 1 or message_line_num > len(transcript_lines):
            print(f"[!] Invalid line number. Transcript has {len(transcript_lines)} messages.")
            return False
        
        # Get message line (1-indexed to 0-indexed)
        message_line = transcript_lines[message_line_num - 1]
        print(f"\n[+] Message {message_line_num}:")
        print(f"    {message_line[:80]}...")
        
        # Parse message: seqno | timestamp | ciphertext | signature | fingerprint
        parts = message_line.split('|')
        if len(parts) != 5:
            print("[!] Invalid message format")
            return False
        
        seqno, timestamp, ciphertext, signature, fingerprint = parts
        
        print(f"\n[+] Message details:")
        print(f"    Sequence: {seqno}")
        print(f"    Timestamp: {timestamp}")
        print(f"    Ciphertext: {ciphertext[:40]}...")
        print(f"    Signature: {signature[:40]}...")
        print(f"    Cert fingerprint: {fingerprint[:32]}...")
        
        # Load certificate
        print(f"\n[+] Loading signer certificate: {signer_cert}")
        cert = CryptoUtils.load_certificate(signer_cert)
        
        cert_fingerprint = CryptoUtils.get_certificate_fingerprint(cert)
        print(f"    Certificate fingerprint: {cert_fingerprint[:32]}...")
        
        # Verify fingerprint matches
        if cert_fingerprint != fingerprint:
            print("\n[✗] Certificate fingerprint mismatch!")
            print("    The certificate does not match the one used to sign this message.")
            return False
        
        print("[✓] Certificate fingerprint matches")
        
        # Verify signature
        print(f"\n[+] Verifying message signature...")
        msg_data = f"{seqno}||{timestamp}||{ciphertext}".encode('utf-8')
        public_key = cert.public_key()
        
        if CryptoUtils.verify_signature(public_key, msg_data, signature):
            print("[✓] Message signature is VALID")
            print("\n" + "="*60)
            print("MESSAGE VERIFICATION SUCCESSFUL!")
            print("="*60)
            print(f"\nMessage {message_line_num} is authentic and has not been tampered with.")
            return True
        else:
            print("[✗] Message signature is INVALID")
            print("\n" + "="*60)
            print("MESSAGE VERIFICATION FAILED!")
            print("="*60)
            print(f"\nMessage {message_line_num} signature could not be verified.")
            print("This indicates tampering!")
            return False
    
    except Exception as e:
        print(f"\n[!] Verification error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main verification menu"""
    print("="*60)
    print("SecureChat Verification Tool")
    print("="*60)
    print("\n1. Verify complete transcript with receipt")
    print("2. Verify individual message signature")
    print("3. Exit")
    
    choice = input("\nSelect option: ").strip()
    
    if choice == '1':
        print("\n" + "-"*60)
        transcript_file = input("Transcript file path: ").strip()
        receipt_file = input("Receipt file path: ").strip()
        cert_file = input("Signer certificate path: ").strip()
        
        verify_transcript(transcript_file, receipt_file, cert_file)
    
    elif choice == '2':
        print("\n" + "-"*60)
        transcript_file = input("Transcript file path: ").strip()
        message_num = int(input("Message line number to verify: ").strip())
        cert_file = input("Signer certificate path: ").strip()
        
        verify_message(transcript_file, message_num, cert_file)
    
    else:
        print("Exiting...")

if __name__ == "__main__":
    # Allow command line usage
    if len(sys.argv) > 1:
        from cryptography import x509  # ← CORRECT
        CryptoUtils.x509 = x509  # ← CORRECT
        
        if sys.argv[1] == 'transcript' and len(sys.argv) == 5:
            verify_transcript(sys.argv[2], sys.argv[3], sys.argv[4])
        elif sys.argv[1] == 'message' and len(sys.argv) == 5:
            verify_message(sys.argv[2], int(sys.argv[3]), sys.argv[4])
        else:
            print("Usage:")
            print("  python3 verify_transcript.py transcript <transcript> <receipt> <cert>")
            print("  python3 verify_transcript.py message <transcript> <line_num> <cert>")
    else:
        main()
