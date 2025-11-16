#!/usr/bin/env python3
"""
Test message tampering detection
Modifies a message in the transcript to simulate tampering
"""

import sys

def tamper_transcript(transcript_file):
    """Modify a message in the transcript to test integrity"""
    print("="*60)
    print("Message Tampering Test")
    print("="*60)
    
    try:
        # Read transcript
        print(f"\n[+] Reading transcript: {transcript_file}")
        with open(transcript_file, 'r') as f:
            lines = f.readlines()
        
        # Find first message line
        message_idx = None
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('#'):
                message_idx = i
                break
        
        if message_idx is None:
            print("[!] No messages found in transcript")
            return
        
        original_line = lines[message_idx]
        print(f"\n[+] Original message (line {message_idx + 1}):")
        print(f"    {original_line[:80].strip()}...")
        
        # Tamper with the message (flip one character in ciphertext)
        parts = original_line.strip().split('|')
        if len(parts) == 5:
            seqno, timestamp, ciphertext, signature, fingerprint = parts
            
            # Flip one character in ciphertext
            if len(ciphertext) > 10:
                tampered_ct = list(ciphertext)
                # Change a character in the middle
                mid = len(tampered_ct) // 2
                if tampered_ct[mid].isalpha():
                    tampered_ct[mid] = 'X' if tampered_ct[mid] != 'X' else 'Y'
                elif tampered_ct[mid].isdigit():
                    tampered_ct[mid] = '9' if tampered_ct[mid] != '9' else '0'
                ciphertext = ''.join(tampered_ct)
            
            tampered_line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{fingerprint}\n"
            lines[message_idx] = tampered_line
            
            print(f"\n[+] Tampered message:")
            print(f"    {tampered_line[:80].strip()}...")
            
            # Create tampered file
            tampered_file = transcript_file.replace('.txt', '_TAMPERED.txt')
            with open(tampered_file, 'w') as f:
                f.writelines(lines)
            
            print(f"\n[✓] Created tampered transcript: {tampered_file}")
            print(f"\n[+] Now verify this transcript with verify_transcript.py")
            print(f"    It should FAIL verification due to hash mismatch")
            print(f"\nCommand:")
            print(f"  python3 verify_transcript.py transcript \\")
            print(f"    {tampered_file} \\")
            print(f"    {transcript_file.replace('transcript', 'receipt').replace('.txt', '.json')} \\")
            print(f"    certs/client.crt")
        
        else:
            print("[!] Invalid message format")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 test_tampering.py <transcript_file>")
        print("\nExample:")
        print("  python3 test_tampering.py transcripts/client_transcript_20251116_174252.txt")
        sys.exit(1)
    
    tamper_transcript(sys.argv[1])
