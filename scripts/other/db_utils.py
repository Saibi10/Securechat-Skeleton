#!/usr/bin/env python3
"""
Database Utilities for SecureChat
Handles user registration, authentication, and database operations.
"""

import pymysql
from dotenv import load_dotenv
import os
from crypto_utils import hash_password, verify_password

# Load environment variables
load_dotenv()

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self):
        """Initialize database connection"""
        self.connection = None
        self.connect()
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = pymysql.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                port=int(os.getenv('DB_PORT', 3306)),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                database=os.getenv('DB_NAME'),
                cursorclass=pymysql.cursors.DictCursor
            )
            print("[+] Database connected successfully")
        except Exception as e:
            print(f"[!] Database connection failed: {e}")
            raise
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("[+] Database connection closed")
    
    def register_user(self, email, username, password):
        """
        Register a new user
        
        Args:
            email: user email
            username: unique username
            password: plaintext password
        
        Returns:
            tuple (success, message)
        """
        try:
            # Hash password with random salt
            pwd_data = hash_password(password)
            
            with self.connection.cursor() as cursor:
                # Check if email already exists
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    return False, "Email already registered"
                
                # Check if username already exists
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return False, "Username already taken"
                
                # Insert new user
                import base64
                sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
                cursor.execute(sql, (
                    email,
                    username,
                    base64.b64decode(pwd_data['salt']),  # Store as binary
                    pwd_data['hash']
                ))
                self.connection.commit()
                
                return True, "Registration successful"
        
        except Exception as e:
            self.connection.rollback()
            return False, f"Registration failed: {str(e)}"
    
    def authenticate_user(self, email, password):
        """
        Authenticate user
        
        Args:
            email: user email
            password: plaintext password
        
        Returns:
            tuple (success, username or error message)
        """
        try:
            with self.connection.cursor() as cursor:
                # Fetch user
                sql = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
                cursor.execute(sql, (email,))
                result = cursor.fetchone()
                
                if not result:
                    return False, "Email not found"
                
                # Verify password
                import base64
                salt_b64 = base64.b64encode(result['salt']).decode('utf-8')
                
                if verify_password(password, salt_b64, result['pwd_hash']):
                    return True, result['username']
                else:
                    return False, "Invalid password"
        
        except Exception as e:
            return False, f"Authentication failed: {str(e)}"
    
    def get_user_info(self, email):
        """Get user information"""
        try:
            with self.connection.cursor() as cursor:
                sql = "SELECT id, email, username, created_at FROM users WHERE email = %s"
                cursor.execute(sql, (email,))
                return cursor.fetchone()
        except Exception as e:
            print(f"[!] Error fetching user info: {e}")
            return None
