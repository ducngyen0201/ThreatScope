import sys
import os
import ctypes
import subprocess

from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, 
                               QSystemTrayIcon, QMenu, QStyle, QMessageBox)
from PySide6.QtGui import QAction, QIcon
from PySide6.QtCore import Qt

from ui.dashboard import DashboardWidget
from ui.detections import DetectionsWidget
from ui.intel_browser import IntelBrowserWidget
from ui.reports import ReportsWidget

# CÁC HÀM HỖ TRỢ TRIỂN KHAI TỰ ĐỘNG (AUTO-DEPLOYMENT)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def ensure_sysmon_ready():
    print("[*] Đang kiểm tra hệ thống Giám sát bảo mật (Sysmon)...")
    
    if getattr(sys, 'frozen', False):
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
        
    sysmon_exe = os.path.join(application_path, "Sysmon64.exe")
    xml_config = os.path.join(application_path, "threatscope_sysmon.xml")
    
    # Kiểm tra xem file đính kèm có tồn tại không
    if not os.path.exists(sysmon_exe) or not os.path.exists(xml_config):
        print("[-] Không tìm thấy gói cài đặt Sysmon đi kèm. Bỏ qua Auto-Setup.")
        return

    cmd = f'"{sysmon_exe}" -accepteula -i "{xml_config}"'
    
    try:
        subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print("[+] Đã nạp thành công cấu hình Sysmon từ gói tích hợp!")
    except Exception as e:
        print(f"[-] Lỗi tự động cấu hình Sysmon: {e}")

# GIAO DIỆN CHÍNH CỦA ỨNG DỤNG (MAIN WINDOW)

class ThreatScopeWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ThreatScope - Windows Threat Intelligence Platform (V2)")
        self.resize(1100, 650)
        
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        self.tab_dashboard = DashboardWidget()
        self.tab_detections = DetectionsWidget()
        self.tab_intel = IntelBrowserWidget()
        self.tab_reports = ReportsWidget(self.tab_detections) 
        
        self.tabs.addTab(self.tab_dashboard, "Tổng quan")
        self.tabs.addTab(self.tab_intel, "Từ điển Tri thức")
        self.tabs.addTab(self.tab_detections, "Phân tích Log EVTX")
        self.tabs.addTab(self.tab_reports, "Xuất Báo cáo")

        # THIẾT LẬP KHAY HỆ THỐNG (SYSTEM TRAY)
        self.tray_icon = QSystemTrayIcon(self)
        icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.tray_icon.setIcon(icon)
        
        tray_menu = QMenu()
        
        show_action = QAction("Khôi phục cửa sổ", self)
        show_action.triggered.connect(self.showNormal)
        
        quit_action = QAction("Kết thúc", self)
        quit_action.triggered.connect(self.force_quit)
        
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.showNormal()
            self.activateWindow()

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "ThreatScope EDR",
            "Hệ thống đang chạy ngầm để giám sát thời gian thực. Nháy đúp vào biểu tượng để mở lại.",
            QSystemTrayIcon.MessageIcon.Information,
            2500
        )

    def force_quit(self):
        if hasattr(self, 'tab_dashboard') and hasattr(self.tab_dashboard, 'edr'):
            self.tab_dashboard.edr.stop()
        self.tray_icon.hide()
        QApplication.instance().quit()

# ENTRY POINT - ĐIỂM KHỞI CHẠY ỨNG DỤNG
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    
    # 1. Cảnh báo nếu không có quyền Admin
    if not is_admin():
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Thiếu quyền quản trị")
        msg.setText("Phần mềm chưa được chạy bằng quyền Administrator (Run as Administrator).\n\nTính năng Tự động cài Sysmon và Tiêu diệt tiến trình (EDR) sẽ không hoạt động!")
        msg.exec()
    else:
        # 2. Tự động kiểm tra và cài đặt cấu hình Sysmon nếu có quyền Admin
        ensure_sysmon_ready()
    
    # 3. Mở giao diện
    window = ThreatScopeWindow()
    window.show()
    sys.exit(app.exec())