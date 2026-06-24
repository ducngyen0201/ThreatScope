import time
import threading
import ctypes
import win32evtlog
import xml.etree.ElementTree as ET
from core.detector import ThreatDetector

class EDRMonitor:
    def __init__(self):
        self.detector = ThreatDetector()
        self.stop_event = threading.Event()
        self.monitor_thread = None
        self.log_channel = "Microsoft-Windows-Sysmon/Operational"
        self.ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        self.alert_callback = None 

    @property
    def is_running(self):
        return self.monitor_thread is not None and self.monitor_thread.is_alive()

    def start(self):
        if self.is_running: return
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(target=self._tail_event_log, daemon=True)
        self.monitor_thread.start()
        print("[+] EDR Realtime Monitor đã được KÍCH HOẠT (Chế độ Polling).")

    def stop(self):
        self.stop_event.set()
        print("[-] Đã phát tín hiệu ĐÓNG EDR. Đang giải phóng tài nguyên...")

    def set_alert_callback(self, callback_func):
        self.alert_callback = callback_func

    def _tail_event_log(self):
        last_record_id = 0
        
        # 1. TÌM CỘT MỐC: Lấy ID của dòng log mới nhất hiện tại
        try:
            init_hand = win32evtlog.EvtQuery(self.log_channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*")
            init_events = win32evtlog.EvtNext(init_hand, 1)
            if init_events:
                xml_content = win32evtlog.EvtRender(init_events[0], win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_content)
                last_record_id = int(root.find(f'.//{self.ns}EventRecordID').text)
            if init_hand: init_hand.Close()
        except:
            pass

        while not self.stop_event.is_set():
            hand = None
            try:
                # 2. XPATH QUYỀN LỰC: Chỉ xin Windows những Log có ID lớn hơn cột mốc
                xpath_query = f"*[System[(EventRecordID > {last_record_id})]]"
                query_flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
                
                hand = win32evtlog.EvtQuery(self.log_channel, query_flags, xpath_query)
                
                # Có thể để 100 thoải mái, vì Windows chỉ trả về log mới. Nếu không có log mới, nó trả về 0.
                events = win32evtlog.EvtNext(hand, 100) 
                
                if events:
                    for event in events:
                        if self.stop_event.is_set(): break
                        
                        xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                        event_dict = self._parse_live_xml(xml_content)
                        
                        if event_dict:
                            record_id = int(event_dict.get('RecordID', 0))
                            
                            alert = self.detector.scan_event(event_dict)
                            if alert:
                                pid = event_dict.get('ProcessId')
                                
                                # Tiêu diệt và báo cáo gọn gàng
                                kill_status = self._kill_malicious_process(pid, alert['Process'])
                                alert['Details'] += f" | Trạng thái: Đã tiêu diệt ({kill_status})"
                                
                                if self.alert_callback:
                                    self.alert_callback(alert)
                                    
                            # Cập nhật cột mốc
                            if record_id > last_record_id:
                                last_record_id = record_id

            except Exception as e:
                if "15007" in str(e):
                    print("[!] LỖI TỬ HUYỆT: Máy tính của bạn chưa được cài đặt Sysmon!")
                    self.stop_event.set()
                    break
                elif "258" not in str(e): # Bỏ qua lỗi Timeout
                    pass
            finally:
                if hand:
                    try:
                        hand.Close()
                    except:
                        pass
            
            time.sleep(0.05)
            
        print("[*] Luồng EDR ngầm đã tắt an toàn.")

    def _parse_live_xml(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            event_id = root.find(f'.//{self.ns}EventID').text
            record_id = root.find(f'.//{self.ns}EventRecordID').text
            
            if event_id not in ['1', '7']: return None

            sys_time = root.find(f'.//{self.ns}TimeCreated').get('SystemTime')[:19].replace('T', ' ')
            event_data = {d.get('Name'): d.text for d in root.find(f'.//{self.ns}EventData').findall(f'{self.ns}Data')}
            
            event_data['EventID'] = event_id
            event_data['RecordID'] = record_id
            event_data['Time'] = sys_time
            return event_data
        except:
            return None

    def _kill_malicious_process(self, pid_str, process_name):
        if not pid_str: return "Không có PID"
        try:
            pid = int(pid_str)
            
            PROCESS_TERMINATE = 1
            
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            
            if not handle:
                return "Từ chối truy cập (Hãy chạy phần mềm bằng Quyền Admin)"

            result = ctypes.windll.kernel32.TerminateProcess(handle, 1)
            
            ctypes.windll.kernel32.CloseHandle(handle)
            
            if result:
                return f"Thành công (API_KILL - PID: {pid})"
            else:
                return "Thất bại (Kẻ địch đã tự sát hoặc có khiên bảo vệ)"
                
        except Exception as e:
            return f"Lỗi cấp thấp: {e}"