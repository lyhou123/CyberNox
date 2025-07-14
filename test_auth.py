#!/usr/bin/env python3
"""
Test authentication system with database
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.database import db

def test_authentication():
    """Test the authentication system"""
    print("🔐 Testing CyberNox Authentication System")
    print("=" * 50)
    
    # Test 1: Check if admin user exists
    print("\n1. Checking admin user...")
    admin_user = db.get_user_by_username('admin')
    
    if admin_user:
        print(f"✅ Admin user found:")
        print(f"   Username: {admin_user['username']}")
        print(f"   Role: {admin_user['role']}")
        print(f"   Email: {admin_user['email']}")
        print(f"   Active: {'Yes' if admin_user['is_active'] else 'No'}")
    else:
        print("❌ Admin user not found")
        return False
    
    # Test 2: Test valid credentials
    print("\n2. Testing valid credentials...")
    valid_user = db.validate_user_credentials('admin', 'admin123')
    
    if valid_user:
        print(f"✅ Valid credentials accepted:")
        print(f"   Username: {valid_user['username']}")
        print(f"   Role: {valid_user['role']}")
    else:
        print("❌ Valid credentials rejected")
        return False
    
    # Test 3: Test invalid credentials
    print("\n3. Testing invalid credentials...")
    invalid_user = db.validate_user_credentials('admin', 'wrongpassword')
    
    if not invalid_user:
        print("✅ Invalid credentials correctly rejected")
    else:
        print("❌ Invalid credentials incorrectly accepted")
        return False
    
    # Test 4: Test non-existent user
    print("\n4. Testing non-existent user...")
    nonexistent_user = db.validate_user_credentials('nonexistent', 'password')
    
    if not nonexistent_user:
        print("✅ Non-existent user correctly rejected")
    else:
        print("❌ Non-existent user incorrectly accepted")
        return False
    
    print("\n" + "=" * 50)
    print("🎉 All authentication tests passed!")
    print("\n📋 Login Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("   Role: admin")
    print("\n🌐 Access the dashboard at: /api/v1/auth/dashboard")
    
    return True

if __name__ == "__main__":
    try:
        test_authentication()
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        sys.exit(1)
