# CyberNox Database & Authentication Setup

## 🎉 Setup Complete!

Your CyberNox project now has a complete SQLite database with user authentication system.

## 🔐 Admin Login Credentials

```
Username: admin
Password: admin123
Role: admin
Email: admin@cybernox.local
```

## 🌐 Access URLs

- **Login Page**: http://127.0.0.1:5000/api/v1/auth/login
- **Admin Dashboard**: http://127.0.0.1:5000/api/v1/auth/dashboard
- **API Status**: http://127.0.0.1:5000/api/v1/status

## 📊 Database Information

- **Database File**: `cybernox.db` (SQLite)
- **Tables**: 9 tables including user authentication
- **Location**: `d:\Cyber lesson\python\CyberNox\cybernox.db`

### Database Tables:
- `users` - User accounts and authentication
- `scan_results` - Scan operation results
- `vulnerabilities` - Security vulnerabilities found
- `targets` - Target information
- `ports` - Port scan data
- `subdomains` - Subdomain enumeration results
- `reports` - Generated security reports
- `configuration` - Application settings

## 🛠️ Database Management Commands

```powershell
# Check database status
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py status

# List all users
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py list-users

# Create new user
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py create-user

# Reset admin password
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py reset-admin

# Reset entire database
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py reset

# Backup database
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py backup

# Restore from backup
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" db_manager.py restore <backup_file>
```

## 🚀 Starting the Server

```powershell
# Start API server
& "D:/Cyber lesson/python/CyberNox/.venv/Scripts/python.exe" start_api.py

# Or use the batch file
start_api_server.bat
```

## 🔑 Authentication Features

- ✅ Secure password hashing with bcrypt
- ✅ JWT token-based authentication
- ✅ Role-based access (admin/user)
- ✅ Login attempt logging
- ✅ Session management
- ✅ Protected admin dashboard
- ✅ Database-driven user management

## 📝 How to Login

1. Start the API server
2. Open http://127.0.0.1:5000/api/v1/auth/login
3. Enter credentials:
   - Username: `admin`
   - Password: `admin123`
4. You'll be redirected to the admin dashboard

## 🔧 Next Steps

- Change the default admin password
- Create additional users as needed
- Customize the dashboard for your needs
- Set up proper SSL certificates for production
- Configure rate limiting and security headers

---

**Note**: The default password `admin123` should be changed in production environments for security.
