import subprocess
import platform
import re
from collections import defaultdict


class WiFiGuard:
    """
    WiFiGuard v1 – Wireless Security Analyzer

    Features:
    - WiFi network scanning
    - Encryption detection
    - Risk classification
    - Signal strength
    - Channel analysis (Linux)
    """

    def __init__(self):
        self.os = platform.system().lower()

    def scan(self):
        if "windows" in self.os:
            return self._scan_windows()
        elif "linux" in self.os:
            return self._scan_linux()
        else:
            return {"error": "Unsupported OS"}

    # =========================
    # WINDOWS SCAN
    # =========================
    def _scan_windows(self):
        try:
            cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
            output = subprocess.check_output(cmd, text=True, errors="ignore")

            networks = []

            ssid = None
            security = None
            signal = None
            channel = None

            for line in output.splitlines():
                line = line.strip()

                if line.startswith("SSID"):
                    ssid = line.split(":", 1)[1].strip()

                elif line.startswith("Authentication"):
                    auth = line.split(":", 1)[1].strip()
                    security = self._normalize_security(auth)

                elif line.startswith("Signal"):
                    signal = line.split(":", 1)[1].strip()

                elif line.startswith("Channel"):
                    channel = line.split(":", 1)[1].strip()
                    risk = self._risk_level(security)

                    networks.append({
                        "ssid": ssid or "Hidden",
                        "security": security or "Unknown",
                        "signal": signal or "—",
                        "channel": channel or "—",
                        "risk": risk
                    })

                    # reset per BSSID
                    signal = None
                    channel = None

            return {
                "networks": networks,
                "channel_congestion": []  # Windows limitation
            }

        except Exception as e:
            return {"error": str(e)}

    # =========================
    # LINUX SCAN
    # =========================
    def _scan_linux(self):
        try:
            cmd = ["nmcli", "-f", "IN-USE,SSID,SECURITY,SIGNAL,CHAN", "dev", "wifi", "list"]
            output = subprocess.check_output(cmd, text=True)

            networks = []
            channel_usage = defaultdict(int)

            for line in output.splitlines()[1:]:
                parts = re.split(r"\s{2,}", line.strip())
                if len(parts) >= 5:
                    _, ssid, security, signal, channel = parts

                    sec = self._normalize_security(security)
                    risk = self._risk_level(sec)
                    channel_usage[channel] += 1

                    networks.append({
                        "ssid": ssid or "Hidden",
                        "security": sec,
                        "signal": f"{signal}%",
                        "channel": channel,
                        "risk": risk
                    })

            congestion = self._channel_congestion(channel_usage)

            return {
                "networks": networks,
                "channel_congestion": congestion
            }

        except Exception as e:
            return {"error": str(e)}

    # =========================
    # HELPERS
    # =========================
    def _normalize_security(self, auth):
        if not auth or auth.lower() in ["--", "none", "open"]:
            return "Open"

        auth = auth.upper()

        if "WEP" in auth:
            return "WEP"
        if "WPA3" in auth:
            return "WPA3"
        if "WPA2" in auth:
            return "WPA2"

        return auth

    def _risk_level(self, security):
        if security == "Open":
            return "High"
        if security == "WEP":
            return "Critical"
        if security == "WPA2":
            return "Medium"
        if security == "WPA3":
            return "Low"
        return "Unknown"

    def _channel_congestion(self, usage):
        """
        Identify congested WiFi channels
        """
        congested = []
        for channel, count in usage.items():
            if count >= 1:
                congested.append({
                    "channel": channel,
                    "networks": count,
                    "risk": "Congested"
                })
        return congested
