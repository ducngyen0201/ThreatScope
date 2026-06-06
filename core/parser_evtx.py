import xml.etree.ElementTree as ET
from evtx import PyEvtxParser

class SysmonEvtxParser:
    def __init__(self, target_eids=None):
        if target_eids is None:
            self.target_eids = ['1', '7', '10', '11']
        else:
            self.target_eids = [str(eid) for eid in target_eids]
            
        self.ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

    def parse_file(self, filepath):
        """Duyệt qua tệp .evtx và trả về dạng Generator"""
        try:
            parser = PyEvtxParser(filepath)
            for record in parser.records():
                event_dict = self._extract_event_data(record['data'])
                if event_dict:
                    yield event_dict
        except Exception as e:
            print(f"[-] Lỗi Parse tệp EVTX {filepath}: {e}")

    def _extract_event_data(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            
            # 1. Trích xuất EventID
            event_id_elem = root.find(f'.//{self.ns}EventID')
            if event_id_elem is None: return None
            event_id = event_id_elem.text
            
            # Chỉ lấy các Event nằm trong danh sách mục tiêu
            if event_id not in self.target_eids: return None

            # 2. Trích xuất Timestamp
            sys_time_elem = root.find(f'.//{self.ns}TimeCreated')
            timestamp = sys_time_elem.get('SystemTime')[:19].replace('T', ' ') if sys_time_elem is not None else "Unknown"

            # 3. Trích xuất dữ liệu chi tiết
            event_data_elem = root.find(f'.//{self.ns}EventData')
            if event_data_elem is None: return None
            
            # Dùng Dictionary Comprehension để trải phẳng dữ liệu
            event_data = {d.get('Name'): d.text for d in event_data_elem.findall(f'{self.ns}Data')}
            
            event_data['EventID'] = event_id
            event_data['Time'] = timestamp
            return event_data
            
        except Exception as e:
            print(f"[!] Bỏ qua một bản ghi do lỗi parse XML: {e}")
            return None