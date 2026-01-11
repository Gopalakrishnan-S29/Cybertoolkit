# tools/techstackprofiler.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

COMMON_TECH = {
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla": ["joomla"],
    "Drupal": ["drupal"],
    "jQuery": ["jquery"],
    "React": ["react"],
    "Vue": ["vue"],
    "Angular": ["angular"],
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


class TechStackProfiler:
    def __init__(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        self.url = url

    def analyze(self):
        result = {
            "url": self.url,
            "server": None,
            "backend": [],
            "cms": [],
            "js": [],
            "security_headers": {},
        }

        try:
            r = requests.get(self.url, timeout=8)
        except Exception as e:
            result["error"] = str(e)
            return result

        # ---- Headers ----
        server = r.headers.get("Server")
        if server:
            result["server"] = server

        # Security headers
        for h in SECURITY_HEADERS:
            result["security_headers"][h] = "Present" if h in r.headers else "Missing"

        # ---- HTML Analysis ----
        soup = BeautifulSoup(r.text, "lxml")
        html = r.text.lower()

        for tech, signs in COMMON_TECH.items():
            for s in signs:
                if s in html:
                    if tech in ["WordPress", "Joomla", "Drupal"]:
                        result["cms"].append(tech)
                    else:
                        result["js"].append(tech)
                    break

        # Backend inference
        cookies = r.headers.get("Set-Cookie", "")
        if "php" in cookies.lower():
            result["backend"].append("PHP")
        if "django" in cookies.lower():
            result["backend"].append("Python (Django)")
        if "flask" in cookies.lower():
            result["backend"].append("Python (Flask)")
        if "node" in cookies.lower():
            result["backend"].append("Node.js")

        return result
