class RiskEngine:
    def __init__(self):
        self.weights = {
            "untrusted_path": 40,
            "unsigned_signature": 40,
            "matched_intel_feed": 20
        }

    def calculate_score(self, is_safe_path, sig_status, has_intel_match):
        score = 0
        details = []

        if not is_safe_path:
            score += self.weights["untrusted_path"]
            details.append("Đường dẫn nạp thư viện bất thường (+40)")
            
        if sig_status in ['unsigned', 'invalid', 'unknownorinvalid']:
            score += self.weights["unsigned_signature"]
            details.append("Chữ ký số không hợp lệ (+40)")

        if has_intel_match:
            score += self.weights["matched_intel_feed"]
            details.append("Khớp với CSDL Mối đe dọa (+20)")

        severity = self._determine_severity(score)
        return score, severity, details

    def _determine_severity(self, score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "INFO"