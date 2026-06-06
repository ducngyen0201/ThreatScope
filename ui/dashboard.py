from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                               QFrame, QPushButton, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QMessageBox)
from PySide6.QtGui import QFont, QColor
from PySide6.QtCore import Qt, Signal, QObject

from core.edr_monitor import EDRMonitor

# Lớp trung gian để truyền tín hiệu an toàn từ luồng EDR ngầm lên Giao diện
class SignalHandler(QObject):
    new_alert = Signal(dict)

class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        
        # Khởi tạo EDR và Cầu nối Tín hiệu
        self.edr = EDRMonitor()
        self.signal_handler = SignalHandler()
        
        # Gắn hàm xử lý khi có tín hiệu cảnh báo mới
        self.signal_handler.new_alert.connect(self.add_live_alert)
        self.edr.set_alert_callback(self.signal_handler.new_alert.emit)
        
        self.setup_ui()
        self.toggle_edr()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Tiêu đề
        title = QLabel("BẢNG ĐIỀU KHIỂN TRUNG TÂM (THREAT DASHBOARD)")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # --- KHUNG THỐNG KÊ (STATS CARDS) ---
        stats_layout = QHBoxLayout()
        self.card_db = self.create_stat_card("Threat Intel DB", "Sẵn sàng", "#1e7145")
        self.card_edr = self.create_stat_card("Trạng thái EDR", "ĐANG TẮT", "#555555")
        
        stats_layout.addWidget(self.card_db)
        stats_layout.addWidget(self.card_edr)
        layout.addLayout(stats_layout)
        
        # --- NÚT ĐIỀU KHIỂN EDR ---
        control_layout = QHBoxLayout()
        self.btn_toggle_edr = QPushButton("🛡️ BẬT LÁ CHẮN EDR (Real-time Monitor)")
        self.btn_toggle_edr.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.btn_toggle_edr.setStyleSheet("background-color: #2b5797; color: white; padding: 15px; border-radius: 5px;")
        self.btn_toggle_edr.clicked.connect(self.toggle_edr)
        
        control_layout.addStretch()
        control_layout.addWidget(self.btn_toggle_edr)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        # --- BẢNG LOG THEO THỜI GIAN THỰC ---
        lbl_log = QLabel("🔴 Hoạt động Giám sát & Tiêu diệt Thời gian thực:")
        lbl_log.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(lbl_log)

        self.table_live = QTableWidget(0, 5)
        self.table_live.setHorizontalHeaderLabels(["Thời gian", "Tiến trình", "Thư viện (DLL)", "Mức độ", "Trạng thái EDR"])
        
        header = self.table_live.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        
        self.table_live.setColumnWidth(0, 150)
        self.table_live.setColumnWidth(1, 150)
        self.table_live.setColumnWidth(2, 180)
        self.table_live.setColumnWidth(3, 100)
        
        layout.addWidget(self.table_live)

    def create_stat_card(self, title, value, color):
        frame = QFrame()
        frame.setStyleSheet(f"background-color: {color}; border-radius: 8px; color: white; padding: 15px;")
        vbox = QVBoxLayout(frame)
        
        lbl_title = QLabel(title)
        lbl_title.setFont(QFont("Segoe UI", 12))
        lbl_title.setAlignment(Qt.AlignCenter)
        
        lbl_value = QLabel(value)
        lbl_value.setFont(QFont("Segoe UI", 14, QFont.Bold))
        lbl_value.setAlignment(Qt.AlignCenter)
        
        # Lưu lại label giá trị để thay đổi text sau này
        frame.lbl_value = lbl_value 
        
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_value)
        return frame

    def toggle_edr(self):
        """Xử lý sự kiện Bật/Tắt EDR"""
        if not self.edr.is_running:
            # Bật EDR
            self.edr.start()
            # Cập nhật giao diện
            self.btn_toggle_edr.setText("⏹️ TẮT LÁ CHẮN EDR")
            self.btn_toggle_edr.setStyleSheet("background-color: #b91d47; color: white; padding: 15px; border-radius: 5px;")
            self.card_edr.setStyleSheet("background-color: #b91d47; border-radius: 8px; color: white; padding: 15px;")
            self.card_edr.lbl_value.setText("ĐANG HOẠT ĐỘNG")
        else:
            # Tắt EDR
            self.edr.stop()
            # Cập nhật giao diện
            self.btn_toggle_edr.setText("🛡️ BẬT LÁ CHẮN EDR (Real-time Monitor)")
            self.btn_toggle_edr.setStyleSheet("background-color: #2b5797; color: white; padding: 15px; border-radius: 5px;")
            self.card_edr.setStyleSheet("background-color: #555555; border-radius: 8px; color: white; padding: 15px;")
            self.card_edr.lbl_value.setText("ĐANG TẮT")

    def add_live_alert(self, alert):
        """Hàm được gọi khi EDR ngầm phát hiện mã độc"""
        row = 0
        self.table_live.insertRow(row)
        
        items = [
            QTableWidgetItem(alert["Time"]),
            QTableWidgetItem(alert["Process"]),
            QTableWidgetItem(alert["DLL"]),
            QTableWidgetItem(alert["Severity"]),
            QTableWidgetItem(alert["Details"])
        ]

        bg_color = QColor("#ffcccc") if alert["Severity"].upper() == "CRITICAL" else QColor("#fff2cc")
        
        for i, item in enumerate(items):
            item.setBackground(bg_color)
            if i == 3: item.setTextAlignment(Qt.AlignCenter)
            
            # Đổi màu chữ Trạng thái EDR (Cột cuối) để làm nổi bật hành động Kill Process
            if i == 4 and "Đã tiêu diệt" in alert["Details"]:
                item.setForeground(QColor("#1e7145"))
                item.setFont(QFont("Segoe UI", 10, QFont.Bold))
                
            self.table_live.setItem(row, i, item)