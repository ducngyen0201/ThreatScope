import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                               QTableWidget, QTableWidgetItem, QFileDialog, 
                               QHeaderView, QMessageBox, QLabel,
                               QDialog, QAbstractItemView, QTextEdit, QFrame)
from PySide6.QtGui import QColor, QFont
from PySide6.QtCore import Qt

from core.parser_evtx import SysmonEvtxParser
from core.detector import ThreatDetector

class DetectionsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.parser = SysmonEvtxParser()
        self.detector = ThreatDetector()
        self.alerts_data = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # --- THANH CÔNG CỤ TÌM KIẾM ---
        top_bar = QHBoxLayout()
        
        self.btn_load_folder = QPushButton("📁 Chọn Thư mục (Batch Scan)")
        self.btn_load_folder.setStyleSheet("background-color: #1e7145; color: white; font-weight: bold; padding: 10px;")
        self.btn_load_folder.clicked.connect(self.load_evtx_folder)

        self.btn_load_file = QPushButton("📄 Chọn 1 Tệp")
        self.btn_load_file.setStyleSheet("background-color: #2b5797; color: white; font-weight: bold; padding: 10px;")
        self.btn_load_file.clicked.connect(self.load_evtx_file)
        
        self.lbl_status = QLabel("Chưa nạp dữ liệu log.")
        self.lbl_status.setFont(QFont("Segoe UI", 10, QFont.Bold))
        
        top_bar.addWidget(self.btn_load_folder)
        top_bar.addWidget(self.btn_load_file)
        top_bar.addStretch()
        top_bar.addWidget(self.lbl_status)
        layout.addLayout(top_bar)

        # --- BẢNG HIỂN THỊ KẾT QUẢ ---
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Tệp Log", "Thời gian", "Tiến trình", "Thư viện (DLL)", "Mức độ", "Kỹ thuật MITRE", "Chi tiết"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 250)
        self.table.setColumnWidth(3, 120)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 120)
        
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.itemDoubleClicked.connect(self.show_alert_details)

        layout.addWidget(self.table)

    def load_evtx_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Chọn tệp Event Log", "", "Windows EVTX (*.evtx)")
        if not filepath: return

        self._prepare_scan(f"Đang quét tệp: {os.path.basename(filepath)}...")
        alerts_found = self._process_file(filepath)
        self._finish_scan(alerts_found)

    def load_evtx_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Chọn thư mục chứa Event Logs")
        if not folder_path: return

        evtx_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.evtx')]
        if not evtx_files:
            QMessageBox.warning(self, "Cảnh báo", "Không tìm thấy tệp .evtx nào trong thư mục này!")
            return

        self._prepare_scan(f"Đang quét thư mục: {os.path.basename(folder_path)} ({len(evtx_files)} tệp)...")
        
        total_alerts = 0
        for filename in evtx_files:
            filepath = os.path.join(folder_path, filename)
            total_alerts += self._process_file(filepath, filename)
            
        self._finish_scan(total_alerts)

    def _prepare_scan(self, status_text):
        self.lbl_status.setText(status_text)
        self.lbl_status.setStyleSheet("color: #b91d47;")
        self.table.setRowCount(0)
        self.alerts_data.clear()

    def _process_file(self, filepath, filename=None):
        if not filename:
            filename = os.path.basename(filepath)
            
        alerts_found = 0
        for event in self.parser.parse_file(filepath):
            alert = self.detector.scan_event(event)
            if alert:
                alert["File"] = filename
                self.add_alert_to_table(alert)
                self.alerts_data.append(alert)
                alerts_found += 1
        return alerts_found

    def _finish_scan(self, alerts_found):
        self.lbl_status.setText(f"Hoàn tất! Phát hiện {alerts_found} cảnh báo.")
        self.lbl_status.setStyleSheet("color: #1e7145;" if alerts_found == 0 else "color: #b91d47;")
        
        if alerts_found == 0:
            QMessageBox.information(self, "An toàn", "Không phát hiện mối đe dọa nào trong(các) tệp Log này.")
        else:
            QMessageBox.warning(self, "Phát hiện Tấn công", f"Đã bóc tách thành công {alerts_found} dấu hiệu vi phạm!")

    def add_alert_to_table(self, alert):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        items = [
            QTableWidgetItem(alert.get("File", "Unknown")),
            QTableWidgetItem(alert["Time"]),
            QTableWidgetItem(alert["Process"]),
            QTableWidgetItem(alert["DLL"]),
            QTableWidgetItem(alert["Severity"]),
            QTableWidgetItem(f"{alert['Technique']} ({alert['Source']})"),
            QTableWidgetItem(alert["Details"])
        ]

        # Tô màu Mức độ
        bg_color = QColor("#ffcccc") if alert["Severity"].upper() == "CRITICAL" else QColor("#fff2cc")
        for i, item in enumerate(items):
            item.setBackground(bg_color)
            if i in [4, 5]: item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, i, item)

    def show_alert_details(self, item):
        row = item.row()
        if row < len(self.alerts_data):
            alert_data = self.alerts_data[row]
            dialog = AlertDetailDialog(alert_data, self)
            dialog.exec()


class AlertDetailDialog(QDialog):
    def __init__(self, alert_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Chi tiết Cảnh báo Hành vi")
        self.setMinimumSize(650, 500)
        
        layout = QVBoxLayout(self)
        
        # --- TIÊU ĐỀ ---
        technique = alert_data.get('Technique', 'Unknown')
        severity = alert_data.get('Severity', 'INFO').upper()
        
        lbl_title = QLabel(f"Mã nhận diện: {technique}")
        lbl_title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        lbl_title.setStyleSheet("color: #b91d47;" if severity == 'CRITICAL' else "color: #d69e2e;" if severity == 'HIGH' else "color: #2b5797;")
        layout.addWidget(lbl_title)
        
        lbl_sub = QLabel(f"Đánh giá rủi ro: {severity} | Nguồn: {alert_data.get('Source', 'N/A')}")
        lbl_sub.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(lbl_sub)
        layout.addSpacing(10)
        
        # --- KHUNG CHỨA THÔNG TIN CHI TIẾT ---
        info_frame = QFrame()
        info_frame.setStyleSheet("background-color: #f1f3f5; border-radius: 5px; border: 1px solid #ced4da;")
        form_layout = QVBoxLayout(info_frame)
        
        # Thêm "Parent Process" vào danh sách hiển thị
        display_keys = ["Time", "File", "Parent Process", "Process", "DLL", "Details"]
        
        for key in display_keys:
            if key in alert_data and alert_data[key]:
                display_name = key
                if key == "Time": display_name = "Thời gian ghi nhận"
                elif key == "File": display_name = "Tệp Log nguồn"
                elif key == "Parent Process": display_name = "Tiến trình Cha (Kẻ kích hoạt / Parent)"
                elif key == "Process": display_name = "Tiến trình con (Vỏ bọc / Image)"
                elif key == "DLL": display_name = "Đối tượng bị tác động (Target / DLL)"
                elif key == "Details": display_name = "Chi tiết hành vi"

                lbl_key = QLabel(f"<b>{display_name}:</b>")
                lbl_key.setFont(QFont("Segoe UI", 10))
                
                txt_val = QTextEdit()
                txt_val.setPlainText(str(alert_data[key]))
                txt_val.setReadOnly(True)
                txt_val.setFont(QFont("Consolas", 10))
                txt_val.setMaximumHeight(55 if key != "Details" else 80)
                txt_val.setStyleSheet("background-color: white; border: 1px solid #dee2e6; border-radius: 3px; padding: 4px;")
                
                form_layout.addWidget(lbl_key)
                form_layout.addWidget(txt_val)
                
        layout.addWidget(info_frame)
        
        # --- NÚT ĐÓNG ---
        btn_layout = QHBoxLayout()
        btn_close = QPushButton("Đóng cửa sổ")
        btn_close.setCursor(Qt.PointingHandCursor) # Chuyển chuột thành hình bàn tay khi di vào
        
        # Áp dụng CSS đồng bộ với bảng điều khiển chính
        btn_close.setStyleSheet("""
            QPushButton { 
                background-color: #e9ecef; 
                border: 1px solid #ced4da; 
                border-radius: 4px; 
                padding: 8px 20px; 
                color: #495057; 
                font-weight: bold;
                font-size: 12px;
            } 
            QPushButton:hover { 
                background-color: #dee2e6; 
                color: #000000; 
                border: 1px solid #adb5bd;
            }
            QPushButton:pressed {
                background-color: #ced4da;
            }
        """)
        btn_close.clicked.connect(self.close)
        
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)