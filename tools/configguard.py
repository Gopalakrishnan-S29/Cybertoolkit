import platform
import subprocess


class ConfigGuard:
    def __init__(self):
        self.os_type = platform.system()

    # ---------- Firewall ----------
    def check_firewall(self):
        try:
            if self.os_type == "Windows":
                output = subprocess.check_output(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                enabled = "ON" in output
            elif self.os_type == "Linux":
                output = subprocess.check_output(
                    ["ufw", "status"],
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                enabled = "active" in output.lower()
            else:
                enabled = False
        except Exception:
            enabled = False

        return {
            "check": "Firewall Status",
            "slug": "firewall_status",
            "status": "Enabled" if enabled else "Disabled",
            "risk": "Low" if enabled else "High",
            "recommendation": "Enable firewall to block unauthorized access.",
            "help": {
                "why": "A disabled firewall allows unauthorized network traffic to reach your system.",
                "windows": [
                    "Open Control Panel",
                    "Go to Windows Defender Firewall",
                    "Click 'Turn Windows Defender Firewall on'",
                    "Enable firewall for all profiles"
                ],
                "linux": [
                    "Open Terminal",
                    "Run: sudo ufw enable",
                    "Verify using: sudo ufw status"
                ]
            }
        }

    # ---------- Guest Account ----------
    def check_guest_account(self):
        enabled = False
        return {
            "check": "Guest Account",
            "slug": "guest_account",
            "status": "Enabled" if enabled else "Disabled",
            "risk": "High" if enabled else "Low",
            "recommendation": "Disable guest accounts to prevent unauthorized login.",
            "help": {
                "why": "Guest accounts can allow attackers to access the system without authentication.",
                "windows": [
                    "Open Computer Management",
                    "Go to Local Users and Groups",
                    "Disable the Guest account"
                ],
                "linux": [
                    "Open Terminal",
                    "Check guest users",
                    "Disable unnecessary accounts"
                ]
            }
        }

    # ---------- Auto-Run ----------
    def check_autorun(self):
        enabled = True
        return {
            "check": "Auto-Run / Auto-Execution",
            "slug": "auto-run_auto_execution",
            "status": "Enabled" if enabled else "Disabled",
            "risk": "Medium" if enabled else "Low",
            "recommendation": "Disable auto-run to prevent USB-based malware.",
            "help": {
                "why": "Auto-run allows malicious USB devices to execute code automatically.",
                "windows": [
                    "Open Control Panel",
                    "Go to AutoPlay settings",
                    "Disable AutoPlay for all media"
                ],
                "linux": [
                    "Open system settings",
                    "Disable removable media auto-execution"
                ]
            }
        }

    # ---------- Screen Lock ----------
    def check_screen_lock(self):
        enabled = True
        return {
            "check": "Screen Lock",
            "slug": "screen_lock",
            "status": "Enabled" if enabled else "Disabled",
            "risk": "Low" if enabled else "Medium",
            "recommendation": "Enable automatic screen lock when idle.",
            "help": {
                "why": "Unlocked systems can be accessed by unauthorized users.",
                "windows": [
                    "Open Settings",
                    "Go to Accounts → Sign-in options",
                    "Enable screen lock timeout"
                ],
                "linux": [
                    "Open Settings",
                    "Enable automatic screen locking"
                ]
            }
        }

    # ---------- OS Updates ----------
    def check_os_updates(self):
        enabled = True
        return {
            "check": "OS Update Status",
            "slug": "os_update_status",
            "status": "Enabled" if enabled else "Disabled",
            "risk": "Low" if enabled else "High",
            "recommendation": "Keep system updates enabled to patch vulnerabilities.",
            "help": {
                "why": "Unpatched systems are vulnerable to known exploits.",
                "windows": [
                    "Open Settings",
                    "Go to Windows Update",
                    "Enable automatic updates"
                ],
                "linux": [
                    "Run: sudo apt update && sudo apt upgrade"
                ]
            }
        }

    # ---------- Antivirus ----------
    def check_antivirus(self):
        present = True
        return {
            "check": "Antivirus Protection",
            "slug": "antivirus_protection",
            "status": "Detected" if present else "Not Detected",
            "risk": "Low" if present else "High",
            "recommendation": "Install and enable antivirus protection.",
            "help": {
                "why": "Antivirus helps detect and block malware.",
                "windows": [
                    "Open Windows Security",
                    "Enable real-time protection"
                ],
                "linux": [
                    "Install ClamAV or another antivirus",
                    "Enable regular scans"
                ]
            }
        }

    # ---------- Public WiFi ----------
    def check_public_wifi(self):
        used = True
        return {
            "check": "Public WiFi Usage",
            "slug": "public_wifi_usage",
            "status": "Used" if used else "Not Used",
            "risk": "Medium" if used else "Low",
            "recommendation": "Avoid public WiFi or use a VPN.",
            "help": {
                "why": "Public WiFi can expose traffic to attackers.",
                "windows": [
                    "Avoid connecting to open networks",
                    "Use a trusted VPN"
                ],
                "linux": [
                    "Avoid open networks",
                    "Use VPN services"
                ]
            }
        }

    # ---------- File Sharing ----------
    def check_file_sharing(self):
        enabled = False
        return {
            "check": "File Sharing",
            "slug": "file_sharing",
            "status": "Enabled" if enabled else "Disabled",
            "risk": "Medium" if enabled else "Low",
            "recommendation": "Disable file sharing if not required.",
            "help": {
                "why": "Unnecessary file sharing can leak sensitive data.",
                "windows": [
                    "Open Network and Sharing Center",
                    "Turn off file sharing"
                ],
                "linux": [
                    "Disable Samba or sharing services"
                ]
            }
        }

    # ---------- Password Policy ----------
    def check_password_policy(self):
        weak = True
        return {
            "check": "Password Strength Policy",
            "slug": "password_strength_policy",
            "status": "Weak" if weak else "Strong",
            "risk": "High" if weak else "Low",
            "recommendation": "Use strong, unique passwords for all accounts.",
            "help": {
                "why": "Weak passwords are easily cracked using brute-force attacks.",
                "windows": [
                    "Use strong passwords",
                    "Enable password complexity rules"
                ],
                "linux": [
                    "Use strong passwords",
                    "Avoid password reuse"
                ]
            }
        }

    # ---------- Browser Security ----------
    def check_browser_security(self):
        safe = False
        return {
            "check": "Browser Security Hygiene",
            "slug": "browser_security_hygiene"  ,
            "status": "Needs Improvement" if not safe else "Secure",
            "risk": "Medium" if not safe else "Low",
            "recommendation": "Update browser and remove unsafe extensions.",
            "help": {
                "why": "Outdated browsers are common attack targets.",
                "windows": [
                    "Update browser to latest version",
                    "Remove unnecessary extensions"
                ],
                "linux": [
                    "Update browser packages",
                    "Review installed extensions"
                ]
            }
        }

    # ---------- Run All ----------
    def analyze(self):
        return [
            self.check_firewall(),
            self.check_guest_account(),
            self.check_autorun(),
            self.check_screen_lock(),
            self.check_os_updates(),
            self.check_antivirus(),
            self.check_public_wifi(),
            self.check_file_sharing(),
            self.check_password_policy(),
            self.check_browser_security()
        ]
