import math
import re
from urllib.parse import urlparse
from typing import Dict, Any

class PhishingDetector:
    """Phishing URL detection engine based on lexical, entropy, and structural heuristics (FR-14)."""

    SUSPICIOUS_KEYWORDS = [
        "login", "verify", "account", "banking", "secure", "update", "signin",
        "confirm", "wallet", "paypal", "appleid", "support", "security", "authenticate"
    ]
    SUSPICIOUS_TLDS = [".xyz", ".top", ".work", ".click", ".fit", ".rest", ".tk", ".ml", ".ga", ".cf"]

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log(p, 2) for p in prob)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Extract URL features and return phishing prediction (FR-14)."""
        url_clean = url.strip()
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "http://" + url_clean

        parsed = urlparse(url_clean)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # Feature Extraction
        length = len(url_clean)
        domain_length = len(domain)
        dot_count = url_clean.count(".")
        hyphen_count = domain.count("-")
        has_at = "@" in url_clean
        is_ip_domain = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain))
        entropy = round(self.calculate_entropy(url_clean), 3)

        # Keyword matching
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in domain or kw in path]
        has_suspicious_tld = any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS)

        # Calculate Phishing Probability
        risk_points = 0.0
        reasons = []

        if is_ip_domain:
            risk_points += 35
            reasons.append("URL domain is a raw IP address instead of a domain name")
        if has_at:
            risk_points += 25
            reasons.append("URL contains '@' credential disguise character")
        if hyphen_count >= 2:
            risk_points += 15
            reasons.append(f"Domain contains excessive hyphens ({hyphen_count})")
        if dot_count >= 4:
            risk_points += 15
            reasons.append(f"Excessive subdomains/dots ({dot_count})")
        if has_suspicious_tld:
            risk_points += 20
            reasons.append("Domain uses a high-risk TLD")
        if found_keywords:
            keyword_score = min(len(found_keywords) * 15, 30)
            risk_points += keyword_score
            reasons.append(f"URL contains high-risk phishing keywords: {', '.join(found_keywords)}")
        if entropy > 4.5:
            risk_points += 15
            reasons.append(f"High string randomness/entropy ({entropy})")
        if length > 75:
            risk_points += 10
            reasons.append("Abnormally long URL length")

        risk_score = min(round(risk_points, 1), 100.0)

        if risk_score >= 65.0:
            classification = "Phishing"
        elif risk_score >= 35.0:
            classification = "Suspicious"
        else:
            classification = "Safe"
            if not reasons:
                reasons.append("No abnormal phishing characteristics detected")

        confidence = round(min(0.5 + (abs(risk_score - 50.0) / 100.0), 0.98), 2)

        return {
            "url": url,
            "classification": classification,
            "risk_score": risk_score,
            "confidence": confidence,
            "reasons": reasons,
            "features": {
                "length": length,
                "domain": domain,
                "entropy": entropy,
                "is_ip_domain": is_ip_domain,
                "keywords_found": found_keywords
            }
        }

phishing_detector = PhishingDetector()
