class WiFiGuardV2Analyzer:
    """
    WiFiGuard v2 – Advanced Passive Wireless Analysis

    Performs explainable wireless security intelligence on top of
    passive scan data from WiFiGuard v1.
    """

    # Standard 2.4GHz overlap model (professional tools)
    OVERLAP_MAP_24GHZ = {
        1: [1, 2, 3, 4, 5],
        6: [2, 3, 4, 5, 6, 7, 8, 9],
        11: [7, 8, 9, 10, 11]
    }

    def __init__(self, scan_data):
        self.networks = scan_data.get("networks", [])
        self.channel_congestion = scan_data.get("channel_congestion", [])

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------
    def summary(self):
        total = len(self.networks)
        high_risk = sum(1 for n in self.networks if n["risk"] in ["High", "Critical"])
        open_networks = sum(1 for n in self.networks if n["security"] == "Open")
        congested_channels = len(self.channel_congestion)

        return {
            "total_networks": total,
            "high_risk": high_risk,
            "open_networks": open_networks,
            "congested_channels": congested_channels
        }

    # --------------------------------------------------
    # ENCRYPTION DISTRIBUTION
    # --------------------------------------------------
    def encryption_distribution(self):
        dist = {}
        for n in self.networks:
            sec = n["security"]
            dist[sec] = dist.get(sec, 0) + 1
        return dist

    # --------------------------------------------------
    # CHANNEL OVERLAP DETECTION (1–6–11)
    # --------------------------------------------------
    def detect_channel_overlap(self):
        channels = []
        for n in self.networks:
            try:
                channels.append(int(n["channel"]))
            except:
                pass

        overlap = []

        for primary, affected in self.OVERLAP_MAP_24GHZ.items():
            count = sum(1 for ch in channels if ch in affected)
            if count >= 2:
                overlap.append({
                    "primary_channel": primary,
                    "affected_channels": affected,
                    "networks": count,
                    "risk": "High Interference"
                })

        return overlap

    # --------------------------------------------------
    # RISK SCORE CALCULATION
    # --------------------------------------------------
    def calculate_risk_score(self, network, congested_channels, overlap_channels):
        score = 0

        # Encryption risk
        if network["security"] == "Open":
            score += 40
        elif network["security"] == "WEP":
            score += 50
        elif network["security"] == "WPA2":
            score += 15
        elif network["security"] == "WPA3":
            score += 5

        # Signal exposure
        try:
            signal = int(network["signal"].replace("%", ""))
            if signal >= 80:
                score += 20
        except:
            pass

        # Channel congestion
        if network["channel"] in congested_channels:
            score += 15

        # Channel overlap
        if network["channel"] in overlap_channels:
            score += 20

        return score

    def risk_from_score(self, score):
        if score >= 70:
            return "Critical"
        if score >= 45:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"

    # --------------------------------------------------
    # RISK REASONING (EXPLAINABLE OUTPUT)
    # --------------------------------------------------
    def risk_reasoning(self):
        analyzed = []

        congested_channels = {c["channel"] for c in self.channel_congestion}
        overlap_info = self.detect_channel_overlap()

        overlap_channels = set()
        for o in overlap_info:
            overlap_channels.update(o["affected_channels"])

        for n in self.networks:
            observations = []

            if n["security"] == "Open":
                observations.append("No encryption enabled")

            if n["security"] == "WEP":
                observations.append("Legacy and insecure encryption")

            try:
                signal = int(n["signal"].replace("%", ""))
                if signal >= 80:
                    observations.append("Strong signal exposure")
            except:
                pass

            if n["channel"] in congested_channels:
                observations.append("Operating on congested channel")

            if n["channel"] in overlap_channels:
                observations.append("Channel overlap interference detected")

            score = self.calculate_risk_score(
                n,
                congested_channels,
                overlap_channels
            )

            analyzed.append({
                "ssid": n["ssid"],
                "security": n["security"],
                "signal": n["signal"],
                "channel": n["channel"],
                "risk_score": score,
                "risk": self.risk_from_score(score),
                "observations": ", ".join(observations) if observations else "No major issues detected"
            })

        return analyzed
