import psycopg
from psycopg.rows import dict_row
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

class ScanDatabase:
    def __init__(self, db_url: str = None):
        # 1. Check if we are in Production
        self.is_production = os.getenv("ENVIRONMENT", "development").lower() == "production"
        
        # 2. Try to get Database URL
        self.db_url = db_url or os.getenv("DATABASE_URL")
        
        # 3. Handle Missing URL
        if not self.db_url:
            if self.is_production:
                print("❌ FATAL: DATABASE_URL is missing in PRODUCTION environment!")
                print("➡️ Please add 'DATABASE_URL' in Render Dashboard -> Environment Variables.")
                self.db_url = None # Explicitly set to None to fail connection later
            else:
                # Fallback only for Local Dev
                print("⚠️  DATABASE_URL not found. Using Localhost fallback...")
                self.db_url = "postgresql://surendrawork@localhost:5432/code_scanner"
        
        # 4. Log usage (Masked)
        if self.db_url:
            masked_url = self.db_url.split("@")[-1] if "@" in self.db_url else "********"
            print(f"🔌 Connecting to Database: ...@{masked_url}")

        if self.db_url:
            self.init_database()
    
    def get_connection(self):
        """Standard connection for PostgreSQL"""
        return psycopg.connect(self.db_url, autocommit=True)

    def init_database(self):
        """Initialize PostgreSQL tables"""
        if not self.db_url:
            return

        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    # Users table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id SERIAL PRIMARY KEY,
                            email TEXT UNIQUE NOT NULL,
                            hashed_password TEXT NOT NULL,
                            full_name TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    
                    # Scans table with user_id
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS scans (
                            id SERIAL PRIMARY KEY,
                            job_id TEXT UNIQUE NOT NULL,
                            user_id INTEGER REFERENCES users(id),
                            repo_url TEXT NOT NULL,
                            status TEXT NOT NULL,
                            total_issues INTEGER DEFAULT 0,
                            security_issues INTEGER DEFAULT 0,
                            quality_issues INTEGER DEFAULT 0,
                            files_scanned INTEGER DEFAULT 0,
                            directories_scanned INTEGER DEFAULT 0,
                            issues TEXT,
                            unit_test_report TEXT,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            completed_at TEXT
                        )
                    """)
                    
                    # Migration: Add user_id to scans if it doesn't exist
                    cur.execute("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name='scans' AND column_name='user_id'
                    """)
                    if not cur.fetchone():
                        print("Adding missing column 'user_id' to scans table...")
                        cur.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
                        
                conn.commit()
        except Exception as e:
            print(f"PostgreSQL initialization error: {e}")
    
    # --- User Management Methods ---
    
    def create_user(self, user_data: Dict) -> Optional[int]:
        """Create a new user"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (email, hashed_password, full_name)
                        VALUES (%s, %s, %s) RETURNING id
                    """, (
                        user_data['email'],
                        user_data['hashed_password'],
                        user_data.get('full_name')
                    ))
                    user_id = cur.fetchone()[0]
                conn.commit()
                return user_id
        except Exception as e:
            print(f"Error creating user: {e}")
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                    return cur.fetchone()
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                    return cur.fetchone()
        except Exception as e:
            print(f"Error getting user by id: {e}")
            return None

    def update_user_password(self, user_id: int, hashed_password: str) -> bool:
        """Update a user's password hash (Migration)"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (hashed_password, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error updating user password: {e}")
            return False

    # --- Scan Management Methods (Updated with user_id) ---

    def save_scan(self, scan_data: Dict) -> bool:
        """Save or update scan data in PostgreSQL"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    query = """
                        INSERT INTO scans 
                        (job_id, user_id, repo_url, status, total_issues, security_issues, quality_issues, 
                         files_scanned, directories_scanned, issues, unit_test_report, 
                         created_at, updated_at, completed_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (job_id) DO UPDATE SET
                            status = EXCLUDED.status,
                            total_issues = EXCLUDED.total_issues,
                            security_issues = EXCLUDED.security_issues,
                            quality_issues = EXCLUDED.quality_issues,
                            files_scanned = EXCLUDED.files_scanned,
                            directories_scanned = EXCLUDED.directories_scanned,
                            issues = EXCLUDED.issues,
                            unit_test_report = EXCLUDED.unit_test_report,
                            updated_at = EXCLUDED.updated_at,
                            completed_at = EXCLUDED.completed_at
                    """
                    cur.execute(query, (
                        scan_data['job_id'],
                        scan_data.get('user_id'),
                        scan_data['repo_url'],
                        scan_data['status'],
                        scan_data.get('total_issues', 0),
                        scan_data.get('security_issues', 0),
                        scan_data.get('quality_issues', 0),
                        scan_data.get('files_scanned', 0),
                        scan_data.get('directories_scanned', 0),
                        json.dumps(scan_data.get('issues', [])),
                        json.dumps(scan_data.get('unit_test_report')) if scan_data.get('unit_test_report') else None,
                        scan_data['created_at'],
                        scan_data['updated_at'],
                        scan_data.get('completed_at')
                    ))
                conn.commit()
                return True
        except Exception as e:
            print(f"PostgreSQL save error: {e}")
            return False
    
    def get_scan(self, job_id: str, user_id: int = None) -> Optional[Dict]:
        """Get scan by job_id from PostgreSQL (optionally filtered by user_id)"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    if user_id:
                        cur.execute("SELECT * FROM scans WHERE job_id = %s AND user_id = %s", (job_id, user_id))
                    else:
                        cur.execute("SELECT * FROM scans WHERE job_id = %s", (job_id,))
                    row = cur.fetchone()
                    if row:
                        scan = dict(row)
                        scan['issues'] = json.loads(scan['issues']) if scan['issues'] else []
                        scan['unit_test_report'] = json.loads(scan['unit_test_report']) if scan['unit_test_report'] else None
                        return scan
                    return None
        except Exception as e:
            print(f"PostgreSQL get error: {e}")
            return None
    
    def get_all_scans(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get all scans for a specific user from PostgreSQL"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("""
                        SELECT job_id, repo_url, status, total_issues, security_issues, 
                               quality_issues, files_scanned, directories_scanned,
                               created_at, completed_at 
                        FROM scans 
                        WHERE user_id = %s
                        ORDER BY created_at DESC 
                        LIMIT %s
                    """, (user_id, limit))
                    return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            print(f"PostgreSQL get_all error: {e}")
            return []
    
    def get_scan_history(self, repo_url: str, user_id: int) -> List[Dict]:
        """Get scan history for specific repository and user from PostgreSQL"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("""
                        SELECT job_id, status, total_issues, security_issues, 
                               quality_issues, files_scanned, directories_scanned,
                               created_at, completed_at 
                        FROM scans 
                        WHERE repo_url = %s AND user_id = %s
                        ORDER BY created_at DESC
                    """, (repo_url, user_id))
                    return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            print(f"PostgreSQL history error: {e}")
            return []
    
    def delete_scan(self, job_id: str, user_id: int) -> bool:
        """Delete scan by job_id for a specific user"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM scans WHERE job_id = %s AND user_id = %s", (job_id, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"PostgreSQL delete error: {e}")
            return False

    def clear_all_scans(self, user_id: int) -> bool:
        """Delete all scans for a specific user"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM scans WHERE user_id = %s", (user_id,))
                conn.commit()
                return True
        except Exception as e:
            print(f"PostgreSQL clear_all error: {e}")
            return False