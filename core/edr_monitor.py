import time
import threading
import psutil
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
        # Cờ truy vấn: Lấy log từ kênh chỉ định và đọc ngược (từ mới nhất về cũ nhất)
        query_flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection

        while not self.stop_event.is_set():
            hand = None
            try:
                # 1. Chủ động chọc thẳng vào DB của Sysmon
                hand = win32evtlog.EvtQuery(self.log_channel, query_flags, "*")
                
                # 2. Rút ra 15 sự kiện mới nhất
                events = win32evtlog.EvtNext(hand, 15)
                
                if events:
                    for event in reversed(events):
                        if self.stop_event.is_set(): break
                        
                        xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                        event_dict = self._parse_live_xml(xml_content)
                        
                        if event_dict:
                            record_id = int(event_dict.get('RecordID', 0))
                            
                            # 3. Chỉ xử lý nếu là sự kiện mới toanh (chưa từng quét)
                            if record_id > last_record_id:
                                if last_record_id != 0: # Bỏ qua vòng lặp đầu tiên để không báo lại log cũ
                                    alert = self.detector.scan_event(event_dict)
                                    if alert:
                                        pid = event_dict.get('ProcessId')
                                        kill_status = self._kill_malicious_process(pid, alert['Process'])
                                        alert['Details'] += f" | EDR: {kill_status}"
                                        
                                        if self.alert_callback:
                                            self.alert_callback(alert)
                                            
                                last_record_id = record_id

            except Exception as e:
                if "15007" in str(e):
                    print("[!] LỖI TỬ HUYỆT: Máy tính của bạn chưa được cài đặt Sysmon!")
                    self.stop_event.set()
                    break
                elif "258" not in str(e):
                    print(f"[-] Cảnh báo luồng EDR: {e}")
            finally:
                # Đóng Handle ngay lập tức sau khi dùng xong
                if hand:
                    try:
                        hand.Close()
                    except:
                        pass
            
            time.sleep(1)
            
        print("[*] Luồng EDR ngầm đã tắt và trả lại tài nguyên cho Windows an toàn 100%.")

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
            p = psutil.Process(pid)
            p.kill()
            return f"Thành công ({pid})"
        except psutil.NoSuchProcess:
            return "Tự tắt"
        except psutil.AccessDenied:
            return "Từ chối truy cập (Cần Admin)"
        except Exception as e:
            return f"Lỗi: {e}"