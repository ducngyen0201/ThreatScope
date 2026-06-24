from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                               QFrame, QPushButton, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QMessageBox,
                               QAbstractItemView, QDialog, QFormLayout, QLineEdit)
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
        lbl_log = QLabel("Hoạt động Giám sát & Tiêu diệt Thời gian thực:")
        lbl_log.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(lbl_log)

        # GIẢM THÔNG TIN BẢNG NGOÀI (Chỉ hiển thị 3 cột)
        self.table_live = QTableWidget(0, 3)
        self.table_live.setHorizontalHeaderLabels(["Thời gian", "Tiến trình (EXE)", "Trạng thái EDR"])
        
        header = self.table_live.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        
        self.table_live.setColumnWidth(0, 160)
        self.table_live.setColumnWidth(1, 180)
        
        layout.addWidget(self.table_live)

        # CẤU HÌNH BẢNG (READ-ONLY)
        self.table_live.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table_live.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_live.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_live.cellDoubleClicked.connect(self.hien_thi_chi_tiet)

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
        
        # Rút gọn trạng thái để hiển thị ở bảng ngoài
        action_text = "Đã tiêu diệt tiến trình" if "Đã tiêu diệt" in alert.get("Details", "") else "Cảnh báo"
        
        item_time = QTableWidgetItem(alert.get("Time", "N/A"))
        item_process = QTableWidgetItem(alert.get("Process", "N/A"))
        item_action = QTableWidgetItem(action_text)

        bg_color = QColor("#ffcccc") if alert.get("Severity", "").upper() == "CRITICAL" else QColor("#fff2cc")
        
        for i, item in enumerate([item_time, item_process, item_action]):
            item.setBackground(bg_color)
            
            item.setData(Qt.UserRole, alert) 
            
            if i == 2 and "tiêu diệt" in action_text:
                item.setForeground(QColor("#1e7145"))
                item.setFont(QFont("Segoe UI", 10, QFont.Bold))
                
            self.table_live.setItem(row, i, item)

    def hien_thi_chi_tiet(self, row, column):
        
        alert_data = self.table_live.item(row, column).data(Qt.UserRole)
        
        if alert_data:
            self.detail_window = LiveAlertDetailWindow(alert_data)
            self.detail_window.show()
        else:
            print("[!] Lỗi: Không tìm thấy dữ liệu ngầm tại ô này.")


# --- LỚP GIAO DIỆN CỬA SỔ POP-UP CHI TIẾT ---
class LiveAlertDetailWindow(QDialog):
    def __init__(self, alert_data):
        super().__init__()
        
        self.setWindowTitle("Chi tiết Cảnh báo Hành vi")
        self.resize(550, 600)
        self.setWindowModality(Qt.NonModal)
        self.setStyleSheet("QDialog { background-color: #f8f9fa; }") # Nền xám nhạt rất nhẹ
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # --- HEADER (Tiêu đề giống ảnh) ---
        lbl_ma = QLabel("<b>Mã nhận diện: T1574.001 (DLL Search Order Hijacking)</b>")
        lbl_ma.setStyleSheet("color: #d97706; font-size: 14px;") # Màu cam đất
        layout.addWidget(lbl_ma)
        
        severity = alert_data.get("Severity", "N/A")
        lbl_rui_ro = QLabel(f"<b>Đánh giá rủi ro: {severity} | Nguồn: Rule Engine</b>")
        lbl_rui_ro.setStyleSheet("color: #333333; font-size: 12px;")
        layout.addWidget(lbl_rui_ro)
        
        # --- KHỐI FORM THÔNG TIN ---
        form_layout = QVBoxLayout()
        form_layout.setSpacing(12)
        
        # Hàm tạo giao diện Box theo chuẩn Forensics
        def create_info_box(label_text, value_text):
            box = QVBoxLayout()
            box.setSpacing(0)
            
            # Tiêu đề box (Nền xám)
            lbl = QLabel(label_text)
            lbl.setStyleSheet("""
                background-color: #e9ecef; 
                border: 1px solid #ced4da; 
                border-bottom: none;
                border-top-left-radius: 4px; 
                border-top-right-radius: 4px;
                padding: 6px; 
                font-weight: bold; 
                color: #495057;
            """)
            
            # Nội dung box (Nền trắng)
            txt = QLineEdit(value_text)
            txt.setReadOnly(True)
            txt.setCursorPosition(0)
            txt.setStyleSheet("""
                background-color: #ffffff; 
                border: 1px solid #ced4da; 
                border-bottom-left-radius: 4px; 
                border-bottom-right-radius: 4px;
                padding: 8px; 
                color: #212529;
            """)
            
            box.addWidget(lbl)
            box.addWidget(txt)
            return box

        raw_details = alert_data.get("Details", "")
        
        dll_path = raw_details.split(" | ")[0].replace("Nạp từ đường dẫn bất thường (", "").replace(")", "") if "|" in raw_details else "N/A"
        
        action_taken = raw_details.split(" | ")[-1].replace("Trạng thái: ", "") if "|" in raw_details else raw_details

        # Thêm các trường dữ liệu
        form_layout.addLayout(create_info_box("Thời gian ghi nhận:", alert_data.get("Time", "N/A")))
        form_layout.addLayout(create_info_box("Tệp tin thực thi (Tiến trình cha / EXE):", alert_data.get("Process", "N/A")))
        form_layout.addLayout(create_info_box("Thư viện bị lạm dụng (Tên tệp DLL):", alert_data.get("DLL", "N/A")))
        form_layout.addLayout(create_info_box("Đường dẫn nạp thư viện:", dll_path))
        form_layout.addLayout(create_info_box("Hành động của hệ thống EDR:", action_taken))
        
        layout.addLayout(form_layout)
        layout.addStretch()
        
        # --- NÚT ĐÓNG ---
        btn_layout = QHBoxLayout()
        btn_close = QPushButton("Đóng cửa sổ")
        btn_close.setFlat(True) # Nút dạng Text phẳng giống ảnh
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.setStyleSheet("QPushButton { color: #495057; font-size: 12px; } QPushButton:hover { color: #000000; font-weight: bold; }")
        btn_close.clicked.connect(self.close)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)