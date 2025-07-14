#!/usr/bin/env python3
"""
Quick script to check SQLite database status
"""

import sqlite3
import os

def check_database():
    db_path = "cybernox.db"
    
    if not os.path.exists(db_path):
        print("❌ Database file not found")
        return
    
    print(f"✅ Database file exists: {db_path}")
    print(f"📊 File size: {os.path.getsize(db_path)} bytes")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print(f"\n📋 Tables in database ({len(tables)}):")
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"  - {table_name}: {count} records")
        
        conn.close()
        print("\n✅ Database check completed successfully")
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

if __name__ == "__main__":
    check_database()
