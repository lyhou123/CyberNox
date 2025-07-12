# 🔐 CyberNox Token Authentication Guide

## 🎯 Token Management & Auto-Redirect System

### **How It Works**

#### **1. Login Process**
- User logs in → Server generates JWT token → Token stored in localStorage
- Token includes expiration time (24 hours)
- Token used for all subsequent API requests

#### **2. Authentication Checks**
- **Page Load**: Check if token exists and is valid
- **API Requests**: Validate token on every request
- **Periodic Check**: Verify token every 5 minutes
- **Auto-Redirect**: Redirect to login if token missing/invalid

#### **3. Logout Process**
- Clear token from localStorage
- Clear all session data
- Redirect to login page

### **Frontend Token Handling**

#### **Dashboard JavaScript** (`/static/js/dashboard.js`)
```javascript
// On page load
checkAuth() → if no token → redirect to login

// Periodic check (every 5 minutes)
setInterval(checkAuth, 300000)

// API requests use makeAuthenticatedRequest()
// Auto-redirects if token invalid
```

#### **Login JavaScript** (`/static/js/login.js`)
```javascript
// On page load
if (token exists && valid) → redirect to dashboard
if (token invalid) → clear token, stay on login
```

### **Backend Token Validation**

#### **API Server** (`api_server.py`)
```python
@auth_required  # Decorator on protected endpoints
def protected_endpoint():
    # Validates JWT token
    # Returns 401 if missing/invalid/expired
    # Includes redirect URL in error response
```

### **Auto-Redirect Scenarios**

#### **Scenario 1: No Token**
```
User access dashboard → No token → Redirect to login
```

#### **Scenario 2: Expired Token**
```
User access dashboard → Token expired → Clear token → Redirect to login
```

#### **Scenario 3: Invalid Token**
```
API request → Token invalid → Clear token → Redirect to login
```

#### **Scenario 4: Valid Token on Login Page**
```
User access login → Token valid → Redirect to dashboard
```

### **API Endpoints**

#### **Authentication Endpoints**
| Endpoint | Method | Purpose |
|----------|---------|---------|
| `/api/v1/auth/login` | GET | Serve login page |
| `/api/v1/auth/login` | POST | Process login |
| `/api/v1/auth/validate` | GET | Validate current token |

#### **Protected Endpoints**
| Endpoint | Method | Purpose |
|----------|---------|---------|
| `/api/v1/dashboard` | GET | Serve dashboard page |
| `/api/v1/dashboard/data` | GET | Get dashboard data |
| `/api/v1/status` | GET | API status (can be used for token check) |

### **Token Storage**

#### **localStorage Keys**
```javascript
'cybernox_token'        // JWT authentication token
'cybernox_remember'     // Remember me preference
'cybernox_activities'   // Activity log
```

#### **Token Format**
```
Header: { "alg": "HS256", "typ": "JWT" }
Payload: { "user": "admin", "exp": 1672531200 }
Signature: HMACSHA256(...)
```

### **Debug & Testing**

#### **Check Token Status (Browser Console)**
```javascript
// Check if token exists
console.log(localStorage.getItem('cybernox_token'));

// Test token validity
fetch('/api/v1/auth/validate', {
    headers: {
        'Authorization': `Bearer ${localStorage.getItem('cybernox_token')}`
    }
}).then(r => r.json()).then(console.log);

// Manual logout
localStorage.removeItem('cybernox_token');
window.location.href = '/api/v1/auth/login';
```

#### **Server-side Token Test**
```bash
# Get token
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "cybernox123"}' | \
  jq -r '.token')

# Test token
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5000/api/v1/auth/validate
```

### **Security Features**

#### **JWT Token Security**
- ✅ Signed with secret key
- ✅ Includes expiration time
- ✅ Validated on every request
- ✅ Cannot be tampered with

#### **Frontend Security**
- ✅ Token stored in localStorage (session-based)
- ✅ Automatic cleanup on logout
- ✅ Periodic validation checks
- ✅ Auto-redirect on auth failure

#### **Backend Security**
- ✅ Rate limiting on login endpoint
- ✅ CORS configuration
- ✅ Comprehensive error handling
- ✅ Audit logging

### **Error Handling**

#### **Common Error Responses**
```json
// Missing token
{
  "error": "Token is missing",
  "redirect": "/api/v1/auth/login"
}

// Expired token
{
  "error": "Token has expired",
  "redirect": "/api/v1/auth/login"
}

// Invalid token
{
  "error": "Token is invalid",
  "redirect": "/api/v1/auth/login"
}
```

#### **Frontend Error Handling**
- All errors include redirect URL
- JavaScript automatically redirects on auth errors
- User-friendly error messages
- Graceful fallback to login page

### **Best Practices**

#### **For Users**
1. Always access via server: `http://127.0.0.1:5000/api/v1/auth/login`
2. Don't open HTML files directly
3. Use incognito mode for testing
4. Clear cache if issues occur

#### **For Developers**
1. Use `makeAuthenticatedRequest()` for API calls
2. Handle auth errors gracefully
3. Test token expiration scenarios
4. Monitor console for auth messages

### **Troubleshooting**

#### **"Token is missing" Error**
- **Cause**: No token in localStorage or malformed Authorization header
- **Solution**: Login again or check browser storage

#### **"Token has expired" Error**
- **Cause**: JWT token past expiration time
- **Solution**: Login again to get new token

#### **"Token is invalid" Error**
- **Cause**: Corrupted or tampered token
- **Solution**: Clear localStorage and login again

#### **Infinite Redirect Loop**
- **Cause**: Both login and dashboard redirecting
- **Solution**: Clear all localStorage and restart server

### **Quick Commands**

#### **Reset Everything**
```javascript
// Browser console
localStorage.clear();
window.location.href = '/api/v1/auth/login';
```

#### **Check Auth Flow**
```javascript
// Test complete flow
console.log('1. Token exists:', !!localStorage.getItem('cybernox_token'));
console.log('2. Current page:', window.location.href);
console.log('3. Running auth check...');
checkAuth();
```

---

## ✅ **Expected Behavior**

1. **No Token**: Immediate redirect to login page
2. **Valid Token**: Access dashboard normally
3. **Expired Token**: Clear token, redirect to login
4. **Logout**: Clear all data, redirect to login
5. **Already Logged In**: Skip login, go to dashboard

The system now provides robust token management with automatic redirects to ensure users are always properly authenticated!
