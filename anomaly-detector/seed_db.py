import sqlite3
import os

DB_PATH = "../traffic.db"

def seed():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create table if not exists (simulate what Go does)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT UNIQUE,
        method TEXT,
        path TEXT,
        query_params TEXT,
        request_headers TEXT,
        request_body TEXT,
        status_code INTEGER,
        response_headers TEXT,
        response_body TEXT,
        timestamp DATETIME
    )
    """)
    
    # Insert 10 normal events for /api/users
    for i in range(10):
        req_id = f"req-{i}"
        req_body = "{\"user\": \"test\"}" # len 16
        res_body = "{\"status\": \"ok\", \"id\": 1}" # len 25
        
        cursor.execute("""
        INSERT OR IGNORE INTO api_traffic (request_id, method, path, request_body, status_code, response_body)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (req_id, "POST", "/api/users", req_body, 201, res_body))
        
    conn.commit()
    conn.close()
    print("Database seeded with normal traffic.")

if __name__ == "__main__":
    seed()
