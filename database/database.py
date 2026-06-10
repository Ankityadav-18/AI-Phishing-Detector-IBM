import sqlite3

def create_database():

    conn = sqlite3.connect("database/history.db")

    cursor = conn.cursor()

    cursor.execute("""
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_text TEXT,
    result TEXT,
    scan_time TEXT
)
""")

    conn.commit()
    conn.close()

create_database()