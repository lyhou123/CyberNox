# 🌐 CyberNox Web Interface - Quick Start

## How to Access the Professional Web Dashboard

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

### Step 2: Open Web Dashboard
1. **Keep the API server running** (don't close the terminal)
2. **Open your web browser** (Chrome, Firefox, Edge, etc.)
3. **Navigate to the web dashboard file**:
   - Open `web_dashboard.html` directly in your browser
   - Or drag and drop `web_dashboard.html` into your browser
   - The file is located at: `d:\Cyber lesson\python\CyberNox\web_dashboard.html`

### Step 3: Login to Dashboard
- **Username**: `admin`
- **Password**: `cybernox123`

## 🔗 Available Endpoints

### API Endpoints (for testing)
- **Root**: http://localhost:5000/ 
- **API Status**: http://localhost:5000/api/v1/status
- **Login**: http://localhost:5000/api/v1/auth/login

### Dashboard Features
✅ **Professional Interface**: Modern Bootstrap 5 design
✅ **Real-time Monitoring**: Live scan progress tracking
✅ **Interactive Charts**: Vulnerability distribution and activity
✅ **Security Tools**: WHOIS, Port scanning, Subdomain enumeration
✅ **Task Management**: Background scan execution
✅ **Professional Reporting**: Multiple export formats

## 🔧 Troubleshooting

### If API server won't start:
```bash
# Check if port 5000 is in use
netstat -ano | findstr :5000

# Use different port if needed
python api_server.py --port 8080
```

### If web dashboard won't connect:
1. Make sure API server is running
2. Check browser console for errors (F12)
3. Verify the API_BASE URL in web_dashboard.html matches your server

### Common Issues:
- **CORS errors**: Make sure API server is running with CORS enabled
- **Authentication failed**: Use credentials admin/cybernox123
- **Connection refused**: API server must be running first

## 🚀 Quick Demo

1. **Start API server**:
   ```bash
   python api_server.py
   ```

2. **Open web dashboard** in browser

3. **Login** with admin/cybernox123

4. **Try a WHOIS lookup**:
   - Go to Reconnaissance tab
   - Enter domain: `google.com`
   - Click Lookup

5. **Try a port scan**:
   - Go to Port Scanning tab
   - Enter target: `google.com`
   - Port range: `80,443`
   - Click Start Scan

## 🎯 Professional Features Demo

### Real-time Dashboard
- View scan statistics
- Monitor active tasks
- See vulnerability distribution

### Advanced Scanning
- Background task execution
- Progress tracking
- Result persistence

### Professional Reporting
- Export scan results
- Generate security reports
- Data visualization

---

**Enjoy your professional CyberNox web interface!** 🛡️
