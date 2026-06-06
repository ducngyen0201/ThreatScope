import sqlite3
import yaml
import os
from datetime import datetime

class ThreatCompiler:
    def __init__(self, db_path="database/threatscope.db"):
        self.db_path = os.path.abspath(db_path)
        self._setup_db()

    def _setup_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS feeds (
                            id INTEGER PRIMARY KEY AUTOINCREMENT, feed_name TEXT UNIQUE)''')
                            
        cursor.execute('''CREATE TABLE IF NOT EXISTS executables (
                            id INTEGER PRIMARY KEY AUTOINCREMENT, exe_name TEXT UNIQUE, expected_paths TEXT)''')
                            
        cursor.execute('''CREATE TABLE IF NOT EXISTS target_dlls (
                            id INTEGER PRIMARY KEY AUTOINCREMENT, exe_id INTEGER, feed_id INTEGER, dll_name TEXT,
                            technique_id TEXT, severity TEXT, author TEXT, vendor TEXT, sha256 TEXT, references_text TEXT, date_added DATETIME,
                            UNIQUE(exe_id, dll_name, feed_id))''')
        conn.commit()
        conn.close()

    def ingest_all_feeds(self, base_dir="feeds"):
        """Quét đệ quy toàn bộ thư mục và file YAML bên trong"""
        stats = {"files_scanned": 0, "rules_added": 0, "errors": []}
        if not os.path.exists(base_dir): 
            return stats

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for root, dirs, files in os.walk(base_dir):
            for file_name in files:
                if file_name.endswith(('.yml', '.yaml')):
                    stats["files_scanned"] += 1
                    file_path = os.path.join(root, file_name)
                    
                    rel_path = os.path.relpath(root, base_dir)
                    if rel_path == '.':
                        feed_name = "Custom Rules"
                    else:
                        top_folder = rel_path.split(os.sep)[0]
                        feed_name = top_folder.replace('_', ' ').title()
                    
                    cursor.execute("INSERT OR IGNORE INTO feeds (feed_name) VALUES (?)", (feed_name,))
                    cursor.execute("SELECT id FROM feeds WHERE feed_name = ?", (feed_name,))
                    feed_id = cursor.fetchone()[0]
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                            if not data: continue
                                
                            dll_name = str(data.get('Name', '')).lower().strip()
                            if not dll_name: continue

                            author = str(data.get('Author', 'Không xác định'))
                            vendor = str(data.get('Vendor', 'Không xác định'))
                            
                            locs = data.get('ExpectedLocations', [])
                            paths = ", ".join(locs) if isinstance(locs, list) else str(locs)

                            refs = data.get('Resources', data.get('References', []))
                            refs_text = "\n".join(refs) if isinstance(refs, list) else str(refs)

                            vulnerabilities = data.get('Vulnerabilities', [])
                            if not vulnerabilities and 'VulnerableExecutables' in data:
                                vulnerabilities = [{'VulnerableExecutables': data['VulnerableExecutables']}]

                            for vuln in vulnerabilities:
                                tech_id = str(vuln.get('MitreID', 'T1574.002'))
                                severity = str(data.get('Severity', 'HIGH'))
                                
                                exes = vuln.get('VulnerableExecutables', [])
                                for exe_item in exes:
                                    exe_path = str(exe_item.get('Path', ''))
                                    exe_name = exe_path.split('\\')[-1].lower() if '\\' in exe_path else exe_path.lower()
                                    if not exe_name: continue

                                    sha_val = exe_item.get('SHA256', [])
                                    sha256 = ", ".join(sha_val) if isinstance(sha_val, list) else str(sha_val)
                                    if not sha256 or sha256 == "[]": sha256 = "Chưa có thông tin"

                                    cursor.execute("INSERT OR IGNORE INTO executables (exe_name, expected_paths) VALUES (?, ?)", (exe_name, paths))
                                    cursor.execute("SELECT id FROM executables WHERE exe_name = ?", (exe_name,))
                                    exe_id = cursor.fetchone()[0]

                                    cursor.execute('''INSERT OR IGNORE INTO target_dlls 
                                                      (exe_id, feed_id, dll_name, technique_id, severity, author, vendor, sha256, references_text, date_added) 
                                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                                   (exe_id, feed_id, dll_name, tech_id, severity, author, vendor, sha256, refs_text, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                                    
                                    if cursor.rowcount > 0:
                                        stats["rules_added"] += 1
                                        
                    except yaml.YAMLError as ye:
                        stats["errors"].append(f"{file_name}: Lỗi cú pháp YAML -> {ye}")
                    except Exception as e:
                        stats["errors"].append(f"{file_name}: Lỗi -> {e}")
                        
        conn.commit()
        conn.close()
        return stats