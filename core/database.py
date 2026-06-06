import sqlite3
import os

class ThreatDatabase:
    def __init__(self, db_path="database/threatscope.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row 
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()

        # BẢNG 1: Feeds
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT UNIQUE NOT NULL,
                description TEXT,
                version TEXT
            )
        ''')

        # BẢNG 2: MITRE ATT&CK
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                technique_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                tactic TEXT NOT NULL
            )
        ''')

        # BẢNG 3: Executables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS executables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exe_name TEXT UNIQUE NOT NULL,
                expected_paths TEXT
            )
        ''')

        # BẢNG 4: Target DLLs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_dlls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exe_id INTEGER,
                dll_name TEXT NOT NULL,
                feed_id INTEGER,
                technique_id TEXT,
                severity TEXT DEFAULT 'HIGH',
                author TEXT,
                vendor TEXT,
                sha256 TEXT,
                references_text TEXT,
                date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (exe_id) REFERENCES executables (id),
                FOREIGN KEY (feed_id) REFERENCES feeds (id),
                FOREIGN KEY (technique_id) REFERENCES mitre_techniques (technique_id),
                UNIQUE(exe_id, dll_name, feed_id)
            )
        ''')

        # BẢNG 5: Valid Indicators
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS valid_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dll_id INTEGER,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                FOREIGN KEY (dll_id) REFERENCES target_dlls (id)
            )
        ''')

        self._seed_initial_data(cursor)
        conn.commit()
        conn.close()

    def _seed_initial_data(self, cursor):
        mitre_data = [
            ('T1574.001', 'DLL Search Order Hijacking', 'Privilege Escalation'),
            ('T1574.002', 'DLL Side-Loading', 'Privilege Escalation')
        ]
        cursor.executemany('INSERT OR IGNORE INTO mitre_techniques (technique_id, name, tactic) VALUES (?, ?, ?)', mitre_data)

if __name__ == "__main__":
    db = ThreatDatabase()