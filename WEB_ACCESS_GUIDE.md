# 🌐 CyberNox Web Interface - Complete Setup Guide

## 🚀 How to Access the Professional Web Interface

### Step 1: Start the API Server
```bash
cd "d:\Cyber lesson\python\CyberNox"
python api_server.py
```

You should see:
```
INFO - Starting CyberNox API server on 127.0.0.1:5000
* Running on http://127.0.0.1:5000
```

### Step 2: Access Login Page via Browser
Open your web browser and go to:
```
http://127.0.0.1:5000/api/v1/auth/login
```

### Step 3: Login with Admin Credentials
- **Username**: `admin`
- **Password**: `cybernox123`
- Click "Access Dashboard"

### Step 4: Automatic Redirect to Dashboard
After successful login, you'll be automatically redirected to:
```
http://127.0.0.1:5000/api/v1/dashboard
```

## 🔄 Complete User Flow

### 1. **Login Process**
- Visit: `http://127.0.0.1:5000/api/v1/auth/login`
- Enter credentials
- System validates login
- JWT token generated and stored
- Automatic redirect to dashboard

### 2. **Dashboard Access**
- URL: `http://127.0.0.1:5000/api/v1/dashboard`
- Protected by authentication
- Real-time data loading
- Professional admin interface

### 3. **Security Features**
- JWT token validation
- Auto-redirect if not authenticated
- Session management
- Activity logging

## 📊 Available Endpoints

### **Public Endpoints**
- `GET /` - API information
- `GET /api/v1/status` - System status
- `GET /api/v1/auth/login` - Login form
- `POST /api/v1/auth/login` - Process login

### **Protected Endpoints** (require authentication)
- `GET /api/v1/dashboard` - Admin dashboard page
- `GET /api/v1/dashboard/data` - Dashboard data
- `POST /api/v1/recon/whois` - WHOIS lookup
- `POST /api/v1/scan/ports` - Port scanning
- `GET /api/v1/tasks` - Task management

## 🔧 Testing the Flow

### 1. **Test Login Endpoint**
```bash
curl http://127.0.0.1:5000/api/v1/auth/login
```
Should return the login HTML page.

### 2. **Test Authentication**
```bash
curl -X POST http://127.0.0.1:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "cybernox123"}'
```
Should return JWT token and success response.

### 3. **Test Dashboard Access**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:5000/api/v1/dashboard
```
Should return the dashboard HTML page.

## 🛡️ Security Features

### **Authentication Flow**
1. User visits login endpoint
2. Credentials validated against database
3. JWT token generated with expiry
4. Token stored in localStorage
5. All subsequent requests include token
6. Token validated on each protected endpoint

### **Session Management**
- 24-hour token expiry
- Auto-logout on token expiration
- Remember me functionality
- Secure token storage

## 🎯 Professional Features

### **Login Page Features**
- Beautiful gradient design
- Real-time API status check
- Auto-filled demo credentials
- Loading states and animations
- Error handling and alerts
- Password visibility toggle
- Keyboard shortcuts (Alt+D for demo)

### **Dashboard Features**
- Real-time metrics and charts
- System status monitoring
- Activity logging and history
- Quick action buttons
- Responsive design
- Professional navigation
- Collapsible sidebar

## 🔄 Development Workflow

### **For Development**
1. Start API server: `python api_server.py`
2. Access via browser: `http://127.0.0.1:5000/api/v1/auth/login`
3. Login with demo credentials
4. Develop and test features

### **For Production**
1. Change default credentials
2. Use HTTPS
3. Configure proper JWT secrets
4. Set up rate limiting
5. Enable logging and monitoring

## 🚨 Troubleshooting

### **Common Issues**

#### **Cannot access login page**
- Check if API server is running
- Verify port 5000 is not blocked
- Check console for errors

#### **Login fails**
- Verify credentials: admin/cybernox123
- Check API server logs
- Ensure POST request format is correct

#### **Dashboard won't load**
- Check if token is stored in localStorage
- Verify token hasn't expired
- Check browser network tab for errors

### **Debug Steps**
1. Open browser developer tools (F12)
2. Check console for JavaScript errors
3. Check network tab for failed requests
4. Verify API server is responding

## ✅ Success Indicators

### **Login Working**
- Login form loads at `/api/v1/auth/login`
- Credentials validate successfully
- JWT token received and stored
- Automatic redirect to dashboard

### **Dashboard Working**
- Dashboard loads at `/api/v1/dashboard`
- Real-time metrics display
- Charts and graphs render
- Navigation menu functional

---

**🎉 Congratulations!** Your CyberNox professional web interface is now fully integrated with the API server!

Access it at: **http://127.0.0.1:5000/api/v1/auth/login**
