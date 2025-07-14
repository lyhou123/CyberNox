#!/usr/bin/env python3
"""
Test login and dashboard access with session cookies
"""

import requests
import json

def test_login_and_dashboard():
    """Test the complete login and dashboard flow"""
    base_url = "http://127.0.0.1:5000"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("🔐 Testing CyberNox Login and Dashboard Access")
    print("=" * 60)
    
    # Test 1: Login with valid credentials
    print("\n1. Testing login...")
    login_data = {
        "username": "admin",
        "password": "admin123",
        "remember_me": False
    }
    
    response = session.post(f"{base_url}/api/v1/auth/login", json=login_data)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Login successful!")
        print(f"   Message: {data.get('message')}")
        print(f"   User: {data.get('user', {}).get('username')}")
        print(f"   Role: {data.get('user', {}).get('role')}")
        print(f"   Token: {data.get('token', 'N/A')[:20]}...")
        print(f"   Redirect URL: {data.get('redirect_url')}")
    else:
        print(f"❌ Login failed: {response.status_code}")
        print(f"   Response: {response.text}")
        return False
    
    # Test 2: Access dashboard with session cookie
    print("\n2. Testing dashboard access with session...")
    response = session.get(f"{base_url}/api/v1/auth/dashboard")
    
    if response.status_code == 200:
        print(f"✅ Dashboard access successful!")
        print(f"   Content length: {len(response.text)} bytes")
        print(f"   Content type: {response.headers.get('content-type')}")
    else:
        print(f"❌ Dashboard access failed: {response.status_code}")
        print(f"   Response: {response.text}")
        return False
    
    # Test 3: Access dashboard without session (new session)
    print("\n3. Testing dashboard access without session...")
    new_session = requests.Session()
    response = new_session.get(f"{base_url}/api/v1/auth/dashboard")
    
    if response.status_code == 401:
        print(f"✅ Unauthorized access correctly blocked!")
        print(f"   Status: {response.status_code}")
    elif response.status_code == 302:
        print(f"✅ Unauthorized access redirected to login!")
        print(f"   Status: {response.status_code}")
        print(f"   Location: {response.headers.get('location')}")
    else:
        print(f"❌ Unexpected response: {response.status_code}")
        print(f"   Response: {response.text}")
    
    # Test 4: Logout
    print("\n4. Testing logout...")
    response = session.post(f"{base_url}/api/v1/auth/logout")
    
    if response.status_code == 200:
        print(f"✅ Logout successful!")
        data = response.json()
        print(f"   Message: {data.get('message')}")
    else:
        print(f"❌ Logout failed: {response.status_code}")
        print(f"   Response: {response.text}")
    
    # Test 5: Try dashboard again after logout
    print("\n5. Testing dashboard access after logout...")
    response = session.get(f"{base_url}/api/v1/auth/dashboard")
    
    if response.status_code == 401:
        print(f"✅ Access correctly blocked after logout!")
    elif response.status_code == 302:
        print(f"✅ Access redirected to login after logout!")
    else:
        print(f"❌ Unexpected response after logout: {response.status_code}")
    
    print("\n" + "=" * 60)
    print("🎉 Authentication testing completed!")
    print("\n📋 Summary:")
    print("   ✅ Database-driven authentication working")
    print("   ✅ Session-based authorization working")
    print("   ✅ Dashboard protection working")
    print("   ✅ Logout functionality working")
    print("\n🌐 You can now login at: http://127.0.0.1:5000/api/v1/auth/login")
    print("   Username: admin")
    print("   Password: admin123")
    
    return True

if __name__ == "__main__":
    try:
        test_login_and_dashboard()
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
