#!/usr/bin/env python3
"""
CyberNox SQLite Database Management Script
Usage: python db_manager.py [command]

Commands:
  status       - Show database status and table info
  reset        - Reset database (removes all data)
  backup       - Create a backup of the database
  restore      - Restore from backup
  create-user  - Create a new user
  list-users   - List all users
  reset-admin  - Reset admin password to default
"""

import sqlite3
import os
import shutil
import sys
from datetime import datetime
from utils.database import CyberNoxDatabase

def show_status():
    """Show database status and information"""
    db_path = "cybernox.db"
    
    if not os.path.exists(db_path):
        print("❌ Database file not found")
        return
    
    print(f"✅ Database file: {db_path}")
    print(f"📊 File size: {os.path.getsize(db_path):,} bytes")
    print(f"📅 Last modified: {datetime.fromtimestamp(os.path.getmtime(db_path))}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print(f"\n📋 Tables ({len(tables)}):")
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"  - {table_name}: {count:,} records")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

def reset_database():
    """Reset the database (removes all data)"""
    db_path = "cybernox.db"
    
    if os.path.exists(db_path):
        print("🗑️  Removing existing database...")
        os.remove(db_path)
    
    print("🔄 Creating fresh database...")
    db = CyberNoxDatabase()
    print("✅ Database reset successfully!")

def backup_database():
    """Create a backup of the database"""
    db_path = "cybernox.db"
    
    if not os.path.exists(db_path):
        print("❌ Database file not found")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"cybernox_backup_{timestamp}.db"
    
    shutil.copy2(db_path, backup_path)
    print(f"✅ Database backed up to: {backup_path}")

def restore_database(backup_file):
    """Restore database from backup"""
    if not os.path.exists(backup_file):
        print(f"❌ Backup file not found: {backup_file}")
        return
    
    db_path = "cybernox.db"
    
    # Backup current database if it exists
    if os.path.exists(db_path):
        current_backup = f"cybernox_before_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(db_path, current_backup)
        print(f"📋 Current database backed up to: {current_backup}")
    
    # Restore from backup
    shutil.copy2(backup_file, db_path)
    print(f"✅ Database restored from: {backup_file}")

def create_user():
    """Create a new user interactively"""
    from utils.database import db
    
    print("🔐 Create New User")
    username = input("Username: ").strip()
    
    if not username:
        print("❌ Username cannot be empty")
        return
    
    password = input("Password: ").strip()
    
    if not password:
        print("❌ Password cannot be empty")
        return
    
    role = input("Role (user/admin) [user]: ").strip() or "user"
    email = input("Email (optional): ").strip() or None
    
    if db.create_user(username, password, role, email):
        print(f"✅ User '{username}' created successfully")
    else:
        print(f"❌ Failed to create user '{username}' (may already exist)")

def list_users():
    """List all users"""
    from utils.database import db
    
    users = db.list_users()
    
    if not users:
        print("📝 No users found")
        return
    
    print(f"👥 Users ({len(users)}):")
    print("-" * 80)
    print(f"{'ID':<5} {'Username':<15} {'Role':<10} {'Email':<25} {'Active':<8} {'Last Login'}")
    print("-" * 80)
    
    for user in users:
        last_login = user['last_login'] or 'Never'
        if last_login != 'Never':
            last_login = last_login[:19]  # Truncate datetime
        
        print(f"{user['id']:<5} {user['username']:<15} {user['role']:<10} "
              f"{user['email'] or 'N/A':<25} {'Yes' if user['is_active'] else 'No':<8} {last_login}")

def reset_admin_password():
    """Reset admin password to default"""
    from utils.database import db
    
    print("🔑 Resetting admin password...")
    
    # Delete existing admin user
    with db.get_connection() as conn:
        conn.execute("DELETE FROM users WHERE username = 'admin'")
        conn.commit()
    
    # Create new admin user
    if db.create_user('admin', 'admin123', 'admin', 'admin@cybernox.local'):
        print("✅ Admin password reset successfully")
        print("   Username: admin")
        print("   Password: admin123")
    else:
        print("❌ Failed to reset admin password")

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    command = sys.argv[1].lower()
    
    if command == "status":
        show_status()
    elif command == "reset":
        reset_database()
    elif command == "backup":
        backup_database()
    elif command == "restore":
        if len(sys.argv) < 3:
            print("❌ Please specify backup file: python db_manager.py restore <backup_file>")
        else:
            restore_database(sys.argv[2])
    elif command == "create-user":
        create_user()
    elif command == "list-users":
        list_users()
    elif command == "reset-admin":
        reset_admin_password()
    else:
        print(f"❌ Unknown command: {command}")
        print(__doc__)

if __name__ == "__main__":
    main()
