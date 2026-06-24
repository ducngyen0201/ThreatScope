import os
import yaml
import fnmatch

class RuleEngine:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules_by_eid = {}
        self.load_all_rules()

    def load_all_rules(self):
        """Quét đệ quy thư mục rules/ và nạp tất cả file YAML vào RAM"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return

        rule_count = 0
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.lower().endswith(('.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            # SỬA LỖI 1: Dùng safe_load_all để đọc file có nhiều block (---)
                            for rule_data in yaml.safe_load_all(f):
                                if not rule_data: 
                                    continue
                                
                                # SỬA LỖI 2: Hỗ trợ linh hoạt cả key "Condition" (cũ) và "Selections" (mới)
                                condition_block = rule_data.get("Condition") or rule_data.get("Selections")
                                
                                if condition_block:
                                    eid = str(condition_block.get("EventID", rule_data.get("EventID", "")))
                                    if eid:
                                        if eid not in self.rules_by_eid:
                                            self.rules_by_eid[eid] = []
                                        self.rules_by_eid[eid].append(rule_data)
                                        rule_count += 1
                    except Exception as e:
                        print(f"[-] Lỗi nạp file luật {file}: {e}")
        print(f"[+] Đã nạp thành công {rule_count} luật hành vi từ thư mục '{self.rules_dir}/'")

    def evaluate(self, event):
        eid = str(event.get('EventID', ''))
        if eid not in self.rules_by_eid:
            return None

        for rule in self.rules_by_eid[eid]:
            # Lấy block điều kiện (hỗ trợ cả Condition và Selections)
            condition = rule.get("Condition") or rule.get("Selections")
            match_condition = True

            # 1. Kiểm tra các điều kiện bắt buộc
            for field, pattern in condition.items():
                if field == "EventID": 
                    continue
                
                event_value = event.get(field, "")
                
                # Nếu mẫu điều kiện là một danh sách (List)
                if isinstance(pattern, list):
                    if not any(self._match_pattern(event_value, p) for p in pattern):
                        match_condition = False
                        break
                # Nếu mẫu điều kiện là một chuỗi đơn (String)
                else:
                    if not self._match_pattern(event_value, pattern):
                        match_condition = False
                        break

            if not match_condition:
                continue

            # 2. Kiểm tra danh sách trắng (Whitelist) để giảm False Positive
            is_whitelisted = False
            whitelist = rule.get("Whitelist", {})
            if whitelist:
                for field, patterns in whitelist.items():
                    event_value = event.get(field, "")
                    if isinstance(patterns, list):
                        if any(self._match_pattern(event_value, p) for p in patterns):
                            is_whitelisted = True
                            break
                    else:
                        if self._match_pattern(event_value, patterns):
                            is_whitelisted = True
                            break

            if not is_whitelisted:
                # Trích xuất dữ liệu đa chiều
                parent_process = event.get("ParentImage", "")
                process_name = event.get("Image", event.get("SourceImage", "Unknown Process"))
                target_object = event.get("ImageLoaded", event.get("TargetImage", "N/A"))
                
                # Đồng bộ tên luật (Hỗ trợ cả RuleName và Name)
                rule_name = rule.get("RuleName") or rule.get("Name", "Behavior")

                return {
                    "Time": event.get('Time', 'N/A'),
                    "Parent Process": parent_process,
                    "Process": process_name,
                    "DLL": target_object, 
                    "Severity": rule.get("Severity", "HIGH").upper(),
                    "Technique": f"{rule.get('MitreID', 'T1548')} ({rule_name})",
                    "Source": "Rule Engine",
                    "Details": rule.get("Description", "Phát hiện hành vi bất thường.")
                }

    def _match_pattern(self, value, pattern):
        if not value or not pattern:
            return False
        return fnmatch.fnmatch(str(value).lower(), str(pattern).lower())


        return None