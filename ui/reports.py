import csv
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QMessageBox)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

class ReportsWidget(QWidget):
    def __init__(self, detections_widget):
        super().__init__()
        self.detections_widget = detections_widget 
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        title = QLabel("KẾT XUẤT BÁO CÁO ĐIỀU TRA (DFIR REPORTS)")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        self.btn_export_csv = QPushButton("Xuất Báo cáo sự cố ra định dạng CSV")
        self.btn_export_csv.setStyleSheet("background-color: #e3a21a; color: white; font-weight: bold; padding: 15px; font-size: 12pt;")
        self.btn_export_csv.clicked.connect(self.export_csv)
        
        layout.addWidget(self.btn_export_csv)
        layout.addStretch()

    def export_csv(self):
        data = self.detections_widget.alerts_data
        if not data:
            QMessageBox.warning(self, "Lỗi", "Chưa có dữ liệu cảnh báo nào để xuất. Vui lòng quét tệp Log trước!")
            return
            
        from PySide6.QtWidgets import QFileDialog
        filepath, _ = QFileDialog.getSaveFileName(self, "Lưu Báo Cáo", "ThreatScope_Incident_Report.csv", "CSV Files (*.csv)")
        
        if filepath:
            with open(filepath, mode='w', newline='', encoding='utf-8-sig') as f:
                import csv
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            QMessageBox.information(self, "Thành công", f"Đã xuất báo cáo pháp y thành công tại:\n{filepath}")