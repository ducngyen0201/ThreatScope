import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import ThreatScopeWindow
from core.database import ThreatDatabase

def main():
    print("[*] Đang kiểm tra hệ thống Database...")
    db = ThreatDatabase()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    white_theme_stylesheet = """
        QMainWindow, QDialog, QMessageBox {
            background-color: #F8F9FA; 
        }
        /* Ép màu chữ mặc định và nền cho các Widget con */
        QWidget {
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 10pt;
            color: #333333;
            background-color: #F8F9FA; /* Vá lỗi nền xám đen của Windows */
        }
        
        /* --- ĐỊNH DẠNG LẠI KHUNG TAB (TAB WIDGET) --- */
        QTabWidget::pane {
            border: 1px solid #CED4DA;
            background-color: #FFFFFF;
            border-radius: 5px;
            margin-top: -1px; /* Đẩy nội dung lên sát mép Tab */
        }
        QTabBar::tab {
            background-color: #E9ECEF;
            color: #495057;
            padding: 8px 20px;
            border: 1px solid #CED4DA;
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #FFFFFF;
            color: #2b5797;
            font-weight: bold;
            border-top: 3px solid #2b5797; /* Đường viền xanh phía trên cho Tab đang chọn */
        }
        QTabBar::tab:hover:!selected {
            background-color: #DEE2E6;
        }

        /* --- CÁC THÀNH PHẦN KHÁC --- */
        QTableWidget {
            background-color: #FFFFFF;
            alternate-background-color: #F1F3F5;
            gridline-color: #DEE2E6;
            border: 1px solid #CED4DA;
            border-radius: 5px;
        }
        QHeaderView::section {
            background-color: #E9ECEF;
            color: #495057;
            padding: 6px;
            border: none;
            border-right: 1px solid #DEE2E6;
            border-bottom: 1px solid #DEE2E6;
            font-weight: bold;
        }
        QPushButton {
            padding: 8px 15px;
            border: none;
            border-radius: 4px;
        }
        QPushButton:disabled {
            background-color: #E9ECEF;
            color: #ADB5BD;
        }
        
        /* Đồng bộ Popup */
        QMessageBox QLabel { color: #333333; }
        QMessageBox QPushButton {
            background-color: #2b5797; 
            color: white;
            min-width: 80px;
        }
        QMessageBox QPushButton:hover { background-color: #1e3f70; }
    """
    app.setStyleSheet(white_theme_stylesheet)

    window = ThreatScopeWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()