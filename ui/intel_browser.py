import sqlite3
import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                               QTableWidget, QTableWidgetItem, 
                               QHeaderView, QLabel, QMessageBox, QPushButton, QLineEdit,
                               QDialog, QGroupBox, QScrollArea, QFrame)
from PySide6.QtGui import QFont, QColor
from PySide6.QtCore import Qt

from core.compiler import ThreatCompiler 

class ThreatDetailDialog(QDialog):
    def __init__(self, detail_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Chi tiết: {detail_data.get('dll_name', 'Unknown')}")
        self.setMinimumSize(850, 600)

        layout = QVBoxLayout(self)
        
        lbl_title = QLabel(str(detail_data.get('dll_name', 'Unknown')))
        lbl_title.setFont(QFont("Segoe UI", 22, QFont.Bold))
        lbl_subtitle = QLabel(f"Có các tệp thực thi cho phép {detail_data.get('dll_name', 'Unknown')} bị lợi dụng để leo quyền.")
        lbl_subtitle.setFont(QFont("Segoe UI", 10))
        
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_subtitle)
        
        info_frame = QFrame()
        info_frame.setStyleSheet("background-color: #f1f3f5; border-radius: 6px;")
        info_layout = QHBoxLayout(info_frame)
        
        col1 = QVBoxLayout()
        col1.addWidget(QLabel(f"<b>Kỹ thuật (MITRE):</b><br>{detail_data.get('technique_id', 'N/A')} - <span style='color:#b91d47;'>{detail_data.get('severity', 'N/A')}</span>"))
        col1.addWidget(QLabel(f"<b>Tác giả:</b><br>{detail_data.get('author', 'N/A')}"))
        
        col2 = QVBoxLayout()
        col2.addWidget(QLabel(f"<b>Nhà cung cấp:</b><br>{detail_data.get('vendor', 'N/A')}"))
        col2.addWidget(QLabel(f"<b>Nguồn (Feed):</b><br>{detail_data.get('feed_name', 'N/A')}"))
        
        col3 = QVBoxLayout()
        # Đã thay đổi thông báo ở ô Mã băm
        col3.addWidget(QLabel(f"<b>Mã băm (SHA256):</b><br><span style='color: #666;'><i>(Được đính kèm chi tiết tại danh sách bên dưới)</i></span>"))
        col3.addWidget(QLabel(f"<b>Ngày cập nhật:</b><br>{detail_data.get('date_added', 'N/A')}"))
        
        info_layout.addLayout(col1)
        info_layout.addLayout(col2)
        info_layout.addLayout(col3)
        layout.addWidget(info_frame)
        layout.addSpacing(10)

        mid_layout = QHBoxLayout()
        
        group_loc = QGroupBox("Vị trí đường dẫn gốc (Expected Locations)")
        group_loc.setFont(QFont("Segoe UI", 10, QFont.Bold))
        loc_layout = QVBoxLayout(group_loc)
        
        raw_paths = str(detail_data.get('expected_paths') or '').split(',')
        paths = sorted(list(set([p.strip() for p in raw_paths if p.strip()])))
        if not paths: paths = ["(Không có dữ liệu vị trí cụ thể)"]
            
        for p in paths:
            lbl_p = QLabel(f"📁 {p}")
            lbl_p.setFont(QFont("Consolas", 10))
            loc_layout.addWidget(lbl_p)
        loc_layout.addStretch()
        
        group_res = QGroupBox("Tài liệu tham khảo (References)")
        group_res.setFont(QFont("Segoe UI", 10, QFont.Bold))
        res_layout = QVBoxLayout(group_res)
        
        refs_text = str(detail_data.get('references_text') or '')
        if refs_text and refs_text != '[]':
            for link in refs_text.split('\n'):
                if link.strip():
                    lbl_link = QLabel(f"🔗 <a href='{link.strip()}'>{link.strip()}</a>")
                    lbl_link.setOpenExternalLinks(True) 
                    res_layout.addWidget(lbl_link)
        else:
            res_layout.addWidget(QLabel("Không có tài liệu đính kèm."))
        res_layout.addStretch()
        
        mid_layout.addWidget(group_loc, stretch=1)
        mid_layout.addWidget(group_res, stretch=1)
        layout.addLayout(mid_layout)

        # LẤY BẢN ĐỒ EXE-HASH TỪ DỮ LIỆU
        exe_details = detail_data.get('exe_details', {})

        group_vuln = QGroupBox(f"Tiến trình bị lợi dụng ({len(exe_details)} EXEs)")
        group_vuln.setFont(QFont("Segoe UI", 10, QFont.Bold))
        vuln_layout = QVBoxLayout(group_vuln)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border: none; background-color: #f8f9fa;")
        scroll_content = QWidget()
        scroll_content.setStyleSheet("background-color: #f8f9fa;")
        scroll_layout = QVBoxLayout(scroll_content)
        
        # VÒNG LẶP VẼ GIAO DIỆN MỚI
        for exe, hashes in sorted(exe_details.items()):
            # 1. Vẽ Tên EXE
            lbl_exe = QLabel(f"📄 {exe}")
            lbl_exe.setFont(QFont("Consolas", 11, QFont.Bold))
            lbl_exe.setStyleSheet("color: #2b5797; margin-top: 6px;")
            scroll_layout.addWidget(lbl_exe)
            
            # 2. Vẽ danh sách Hash nằm thụt lề bên dưới
            if hashes:
                for h in sorted(hashes):
                    lbl_hash = QLabel(f"   ↳ Hash: <span style='font-family: Consolas; font-size: 11px; color: #555;'>{h}</span>")
                    scroll_layout.addWidget(lbl_hash)
            else:
                lbl_hash = QLabel(f"   ↳ Hash: <span style='font-family: Consolas; font-size: 11px; color: #999;'><i>(Không có dữ liệu Hash)</i></span>")
                scroll_layout.addWidget(lbl_hash)
                
        scroll_layout.addStretch()
        
        scroll.setWidget(scroll_content)
        vuln_layout.addWidget(scroll)
        layout.addWidget(group_vuln)

        btn_layout = QHBoxLayout()
        btn_close = QPushButton("Đóng cửa sổ")
        btn_close.setFixedWidth(120)
        btn_close.setMinimumHeight(30)
        btn_close.clicked.connect(self.close)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

class IntelBrowserWidget(QWidget):
    def __init__(self, db_path="database/threatscope.db"):
        super().__init__()
        self.db_path = os.path.abspath(db_path)
        self.setup_ui()
        self.load_all_intel()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        title = QLabel("TỪ ĐIỂN TRI THỨC MỐI ĐE DỌA (THREAT INTEL DB)")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        top_layout.addWidget(title)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Nhập tên DLL, EXE hoặc MITRE... (Nháy đúp vào dòng để xem chi tiết)")
        self.search_bar.setMinimumWidth(400)
        self.search_bar.setStyleSheet("padding: 5px; border: 1px solid #ccc; border-radius: 4px; font-size: 13px;")
        self.search_bar.textChanged.connect(self.filter_table)
        top_layout.addWidget(self.search_bar)
        
        top_layout.addStretch()

        self.btn_update = QPushButton("Nạp Luật Mới")
        self.btn_update.setStyleSheet("background-color: #d24726; color: white; padding: 6px 12px; font-weight: bold; border-radius: 4px;")
        self.btn_update.clicked.connect(self.run_auto_updater)
        top_layout.addWidget(self.btn_update)

        layout.addLayout(top_layout)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Thư viện bị lạm dụng (DLL)", "Các tiến trình Mục tiêu (EXEs)", 
            "Kỹ thuật MITRE", "Mức độ", "Nguồn (Feed)", "Ngày cập nhật"
        ])
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        
        # --- ĐIỀU CHỈNH ĐỘ RỘNG CÁC CỘT TẠI ĐÂY ---
        self.table.setColumnWidth(0, 250) 
        self.table.setColumnWidth(1, 250) 
        self.table.setColumnWidth(2, 120) 
        self.table.setColumnWidth(3, 100) 
        self.table.setColumnWidth(4, 120) 
        self.table.setColumnWidth(5, 150) 
        
        # Bật tính năng click vào tiêu đề cột để sắp xếp
        self.table.setSortingEnabled(True)
        
        self.table.itemDoubleClicked.connect(self.show_detail_dialog)
        layout.addWidget(self.table)

    def show_detail_dialog(self, item):
        row = item.row()
        dll_name = self.table.item(row, 0).text()
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT e.exe_name, e.expected_paths, 
                   t.technique_id, t.severity, f.feed_name, 
                   t.date_added, t.author, t.vendor, t.sha256, t.references_text
            FROM target_dlls t
            JOIN executables e ON t.exe_id = e.id
            JOIN feeds f ON t.feed_id = f.id
            WHERE t.dll_name = ?
        '''
        try:
            cursor.execute(query, (dll_name,))
            rows = cursor.fetchall()
            
            if not rows: return

            paths = set()
            refs = set()
            exe_details = {} # SỬ DỤNG DICTIONARY ĐỂ MAP EXE VÀ HASH

            base_info = {
                'dll_name': dll_name,
                'technique_id': rows[0]['technique_id'],
                'severity': rows[0]['severity'],
                'feed_name': rows[0]['feed_name'],
                'date_added': rows[0]['date_added'],
                'author': rows[0]['author'],
                'vendor': rows[0]['vendor']
            }

            for r in rows:
                exe_name = str(r['exe_name']) if r['exe_name'] else "Unknown"
                
                # Khởi tạo danh sách Hash cho EXE nếu chưa có
                if exe_name not in exe_details:
                    exe_details[exe_name] = set()

                # Ghép đúng Hash vào đúng EXE đang xét
                if r['sha256'] and r['sha256'] != 'Chưa có thông tin':
                    for s in str(r['sha256']).split(','):
                        if s.strip():
                            exe_details[exe_name].add(s.strip())

                if r['expected_paths']:
                    for p in str(r['expected_paths']).split(','):
                        if p.strip(): paths.add(p.strip())
                        
                if r['references_text']:
                    for ref in str(r['references_text']).split('\n'):
                        if ref.strip(): refs.add(ref.strip())

            base_info['expected_paths'] = ",".join(paths)
            base_info['references_text'] = "\n".join(refs)
            base_info['exe_details'] = exe_details

            dialog = ThreatDetailDialog(base_info, self)
            dialog.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Lấy Dữ Liệu", f"Chi tiết:\n{e}")
        finally:
            conn.close()

    def filter_table(self, text):
        search_text = text.lower()
        for row in range(self.table.rowCount()):
            match_found = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and search_text in item.text().lower():
                    match_found = True
                    break
            self.table.setRowHidden(row, not match_found)

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def run_auto_updater(self):
        feeds_base_dir = os.path.abspath("feeds")
        if not os.path.exists(feeds_base_dir):
            os.makedirs(feeds_base_dir)
            
        self.btn_update.setText("Đang phân tích...")
        self.btn_update.setEnabled(False)
        from PySide6.QtWidgets import QApplication
        QApplication.processEvents() 

        try:
            compiler = ThreatCompiler(self.db_path)
            stats = compiler.ingest_all_feeds(feeds_base_dir)
            
            msg = f"BÁO CÁO CẬP NHẬT CƠ SỞ DỮ LIỆU:\n"
            msg += f"Quét tại: {feeds_base_dir}\n"
            msg += f"----------------------------------\n"
            msg += f"Số file YAML tìm thấy: {stats['files_scanned']}\n"
            msg += f"Số luật đã nạp thành công: {stats['rules_added']}\n"
            
            if stats['errors']:
                msg += f"\nCÓ {len(stats['errors'])} LỖI NHỎ XẢY RA (Xem Console để biết chi tiết)."
                for err in stats['errors'][:5]: print(err)
                QMessageBox.warning(self, "Cập nhật hoàn tất (Có cảnh báo)", msg)
            elif stats['files_scanned'] == 0:
                msg += f"\nCHÚ Ý: Thư mục Feeds đang trống!"
                QMessageBox.warning(self, "Không tìm thấy dữ liệu", msg)
            else:
                QMessageBox.information(self, "Cập nhật thành công", msg)

            self.load_all_intel()
            
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Hệ thống", f"Lỗi không xác định:\n{e}")
        finally:
            self.btn_update.setText("Nạp Luật Mới")
            self.btn_update.setEnabled(True)

    def load_all_intel(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT t.dll_name, 
                   GROUP_CONCAT(e.exe_name, ',') as exe_names, 
                   t.technique_id, t.severity, f.feed_name, MAX(t.date_added) as date_added
            FROM target_dlls t
            JOIN executables e ON t.exe_id = e.id
            JOIN feeds f ON t.feed_id = f.id
            GROUP BY t.dll_name, t.technique_id, t.severity, f.feed_name
            ORDER BY date_added DESC
        '''
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            
            # Tạm tắt sắp xếp để chèn dữ liệu không bị lỗi nhảy dòng
            self.table.setSortingEnabled(False)
            self.table.setRowCount(0)
            
            for row in rows:
                r = self.table.rowCount()
                self.table.insertRow(r)
                
                self.table.setItem(r, 0, QTableWidgetItem(str(row['dll_name'] or 'Unknown')))
                
                raw_exes = str(row['exe_names'] or '')
                exes_list = sorted(list(set([x.strip() for x in raw_exes.split(',') if x.strip()])))
                self.table.setItem(r, 1, QTableWidgetItem(", ".join(exes_list)))
                
                item_mitre = QTableWidgetItem(str(row['technique_id'] or ''))
                item_mitre.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(r, 2, item_mitre)
                
                severity = str(row['severity'] or 'UNKNOWN')
                item_sev = QTableWidgetItem(severity)
                item_sev.setTextAlignment(Qt.AlignCenter)
                if severity == 'CRITICAL':
                    item_sev.setForeground(QColor("#b91d47"))
                    item_sev.setFont(QFont("Segoe UI", 10, QFont.Bold))
                self.table.setItem(r, 3, item_sev)

                item_feed = QTableWidgetItem(str(row['feed_name'] or ''))
                item_feed.setFont(QFont("Segoe UI", 10, QFont.Bold))
                self.table.setItem(r, 4, item_feed)
                
                self.table.setItem(r, 5, QTableWidgetItem(str(row['date_added'] or '')))
                
            # Bật lại tính năng sắp xếp
            self.table.setSortingEnabled(True)
            
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Tải Bảng", f"Không thể hiển thị dữ liệu:\n{e}")
        finally:
            conn.close()