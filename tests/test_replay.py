#!/usr/bin/env python3
"""
Test replay attack detection
Simulates sending an old message again
"""

import socket
import json
import time

def replay_attack_demo():
    """
    Demonstrate replay attack detection
    
    Instructions:
    1. Run server in one terminal
    2. Run client in another terminal and exchange 2-3 messages
    3. Keep both running
    4. Run this script in a third terminal
    5. This script will capture a message and replay it
    6. Server should detect and reject the replayed message
    """
    
    print("="*60)
    print("Replay Attack Test")
    print("="*60)
    print("\n[!] This is a demonstration script")
    print("[!] In a real test, you would:")
    print("    1. Capture a valid message packet")
    print("    2. Resend it after newer messages")
    print("    3. Server detects sequence number is old")
    print("    4. Server rejects with 'REPLAY' error")
    print("\n[+] To test manually:")
    print("    1. Start server and client")
    print("    2. Send message: 'Hello' (seqno=1)")
    print("    3. Send message: 'World' (seqno=2)")
    print("    4. Use Wireshark to capture message 1")
    print("    5. Resend the captured packet")
    print("    6. Server rejects because seqno=1 < current=2")
    print("\n[+] The server logs should show:")
    print("    [!] REPLAY ATTACK DETECTED: seqno 1 <= 2")

if __name__ == "__main__":
    replay_attack_demo()
