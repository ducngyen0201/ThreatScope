import os
import sqlite3

from core.rule_engine import RuleEngine

class ThreatDetector:
    def __init__(self, db_path="database/threatscope.db"):
        self.db_path = db_path
        self.rule_engine = RuleEngine(rules_dir="rules")

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def scan_event(self, event):
        """Hàm lõi nhận xử lý từng dòng log truyền xuống từ UI"""
        if not event: 
            return None

        # --- TẦNG LỌC 1: ĐỐI CHIẾU DATABASE (DÀNH RIÊNG CHO EVENT ID 7 - DLL HIJACKING) ---
        if str(event.get('EventID')) == '7':
            alert_from_db = self._check_dll_sideloading_with_db(event)
            if alert_from_db:
                return alert_from_db

        # --- TẦNG LỌC 2: ĐỐI CHIẾU RULE ENGINE (ĐA DẠNG HÀNH VI: EVENT 1, 10, 11...) ---
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
        
        conn = self._get_connection()
        cursor = conn.cursor()

        # 1. Truy vấn xem Tiến trình và DLL có nằm trong danh sách theo dõi không
        query = '''
            SELECT t.id as dll_id, t.technique_id, t.severity, f.feed_name, e.expected_paths
            FROM target_dlls t
            JOIN executables e ON t.exe_id = e.id
            JOIN feeds f ON t.feed_id = f.id
            WHERE LOWER(e.exe_name) = ? AND LOWER(t.dll_name) = ?
        '''
        cursor.execute(query, (exe_name, dll_name))
        match = cursor.fetchone()

        if not match:
            conn.close()
            return None

        # 2. Phát hiện: Kẻ tấn công thường nạp DLL từ thư mục bất thường (Temp, AppData...)
        expected_paths = match['expected_paths'].lower().split(',') if match['expected_paths'] else []
        is_safe_path = any(safe_dir in dll_path.lower() for safe_dir in expected_paths) if expected_paths else True
        
        # 3. Phân tích Chữ ký số
        sig_status = event.get('SignatureStatus', '').lower()
        
        # TÍNH TOÁN RỦI RO (RISK SCORING)
        is_malicious = False
        reason = []

        if not is_safe_path:
            is_malicious = True
            reason.append(f"Nạp từ đường dẫn bất thường ({dll_path})")
            
        if sig_status in ['unsigned', 'invalid']:
            is_malicious = True
            reason.append("Chữ ký số không hợp lệ hoặc bị thiếu")

        conn.close()

        if is_malicious:
            return {
                "Time": event.get('Time'),
                "Process": exe_name,
                "DLL": dll_name,
                "Severity": match['severity'],
                "Technique": match['technique_id'],
                "Source": match['feed_name'],
                "Details": " | ".join(reason)
            }
            
        return None