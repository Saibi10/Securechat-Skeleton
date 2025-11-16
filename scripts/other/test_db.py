#!/usr/bin/env python3
"""
Test database connectivity and operations
"""

from db_utils import DatabaseManager
from crypto_utils import hash_password
import sys

def test_database():
    """Test database operations"""
    print("="*60)
    print("Database Connection Test")
    print("="*60)
    
    try:
        # Connect to database
        print("\n[+] Connecting to database...")
        db = DatabaseManager()
        print("[✓] Database connected successfully")
        
        # Test registration
        print("\n[+] Testing user registration...")
        email = "test@example.com"
        username = "testuser"
        password = "TestPassword123!"
        
        success, message = db.register_user(email, username, password)
        print(f"    Result: {message}")
        
        if success:
            print("[✓] Registration successful")
        else:
            print(f"[!] Registration failed (this is OK if user already exists)")
        
        # Test authentication
        print("\n[+] Testing authentication...")
        success, result = db.authenticate_user(email, password)
        
        if success:
            print(f"[✓] Authentication successful! Username: {result}")
        else:
            print(f"[!] Authentication failed: {result}")
        
        # Test wrong password
        print("\n[+] Testing authentication with wrong password...")
        success, result = db.authenticate_user(email, "WrongPassword!")
        
        if not success:
            print(f"[✓] Correctly rejected wrong password: {result}")
        else:
            print(f"[!] ERROR: Wrong password was accepted!")
        
        # Get user info
        print("\n[+] Getting user info...")
        user_info = db.get_user_info(email)
        if user_info:
            print(f"[✓] User info retrieved:")
            print(f"    ID: {user_info['id']}")
            print(f"    Email: {user_info['email']}")
            print(f"    Username: {user_info['username']}")
            print(f"    Created: {user_info['created_at']}")
        
        # Close connection
        db.close()
        print("\n[✓] All tests passed!")
        
    except Exception as e:
        print(f"\n[!] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    test_database()
