import os
import sqlite3

from core.rule_engine import RuleEngine

class ThreatDetector:
    def __init__(self, db_path="database/threatscope.db"):
        self.db_path = db_path
        self.rule_engine = RuleEngine(rules_dir="rules")
        
        self.dll_cache = {} 
        self._load_db_to_cache()

    def _load_db_to_cache(self):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = '''
                SELECT LOWER(e.exe_name) as exe_name, LOWER(t.dll_name) as dll_name, 
                       t.technique_id, m.name as technique_name, t.severity, f.feed_name, e.expected_paths
                FROM target_dlls t
                JOIN executables e ON t.exe_id = e.id
                JOIN feeds f ON t.feed_id = f.id
                LEFT JOIN mitre_techniques m ON t.technique_id = m.technique_id
            '''
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                cache_key = f"{row['exe_name']}|{row['dll_name']}"
                self.dll_cache[cache_key] = dict(row)
                
            conn.close()
            print(f"[+] Lõi Nhận diện: Đã nạp {len(self.dll_cache)} luật DLL vào bộ đệm RAM thành công.")
        except Exception as e:
            print(f"[!] Lỗi nạp Database Cache: {e}")

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def scan_event(self, event):
        if not event: 
            return None

        event_id = str(event.get('EventID', ''))

        if event_id == '7':
            exe_path = event.get('Image', '').lower()
            dll_path = event.get('ImageLoaded', '').lower()
            
            whitelist_paths = [
                '\\programdata\\microsoft\\',
                '\\program files (x86)\\microsoft\\',
                '\\program files\\microsoft\\',
                '\\program files\\google\\',
                '\\windows\\system32\\',
                '\\windows\\syswow64\\',
                '\\windows\\winsxs\\'
            ]
            
            if exe_path and any(safe_dir in exe_path for safe_dir in whitelist_paths):
                return None
            if dll_path and any(safe_dir in dll_path for safe_dir in whitelist_paths):
                return None
                
            alert_from_db = self._detect_dll_hijacking(event)
            if alert_from_db:
                return alert_from_db

        alert_from_rules = self.rule_engine.evaluate(event)
        if alert_from_rules:
            return alert_from_rules

        return None

    def _detect_dll_hijacking(self, event):
        exe_path = event.get('Image', '')
        dll_path = event.get('ImageLoaded', '')
        
        if not exe_path or not dll_path: return None

        exe_name = os.path.basename(exe_path).lower()
        dll_name = os.path.basename(dll_path).lower()
        
        cache_key = f"{exe_name}|{dll_name}"
        match = self.dll_cache.get(cache_key)

        if not match:
            return None

        expected_paths = match['expected_paths'].lower().split(',') if match['expected_paths'] else []
        is_safe_path = any(safe_dir in dll_path.lower() for safe_dir in expected_paths) if expected_paths else True
        
        sig_status = event.get('SignatureStatus', '').lower()

        is_malicious = False
        reason = []

        if not is_safe_path:
            is_malicious = True
            reason.append(f"Nạp từ đường dẫn bất thường ({dll_path})")
            
        if sig_status in ['unsigned', 'invalid']:
            is_malicious = True
            reason.append("Chữ ký số không hợp lệ hoặc bị thiếu")

        if is_malicious:
            return {
                "Time": event.get('Time'),
                "Process": exe_name,
                "DLL": dll_name,
                "Severity": match['severity'],
                "Technique": match['technique_id'],
                "TechniqueName": match['technique_name'],
                "Source": match['feed_name'],
                "Details": " | ".join(reason)
            }
            
        return None