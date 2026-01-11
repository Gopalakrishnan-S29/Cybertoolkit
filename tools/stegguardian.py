from PIL import Image
import math
import os


class StegGuardian:
    def __init__(self, image_path):
        self.image_path = image_path

        # Ensure image is in RGB (important for consistency)
        self.image = Image.open(image_path).convert("RGB")

        self.pixels = list(self.image.getdata())
        self.width, self.height = self.image.size
        self.file_size = os.path.getsize(image_path)

    # ---------- Entropy Calculation ----------
    def calculate_entropy(self):
        freq = {}

        for pixel in self.pixels:
            r, g, b = pixel
            freq[r] = freq.get(r, 0) + 1
            freq[g] = freq.get(g, 0) + 1
            freq[b] = freq.get(b, 0) + 1

        entropy = 0.0
        total = sum(freq.values())

        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        return round(entropy, 2)

    # ---------- LSB Analysis ----------
    def lsb_anomaly_score(self):
        ones = 0
        total_bits = 0

        for pixel in self.pixels:
            for channel in pixel:
                ones += (channel & 1)
                total_bits += 1

        zeros = total_bits - ones

        if zeros == 0:
            return 1.0

        ratio = ones / zeros
        return round(ratio, 2)

    # ---------- File Size Anomaly ----------
    def size_anomaly(self):
        # Expected raw RGB size (approx)
        expected_size = self.width * self.height * 3
        return self.file_size > expected_size * 1.5

    # ---------- Final Analysis ----------
    def analyze(self):
        entropy = self.calculate_entropy()
        lsb_score = self.lsb_anomaly_score()
        size_flag = self.size_anomaly()

        # Risk classification
        if entropy > 7.8 and lsb_score > 1.1:
            risk = "High"
        elif entropy > 7.5 or lsb_score > 0.9 or size_flag:
            risk = "Medium"
        else:
            risk = "Low"

        return {
            "resolution": f"{self.width} x {self.height}",
            "file_size_kb": round(self.file_size / 1024, 2),
            "entropy": entropy,
            "lsb_score": lsb_score,
            "size_anomaly": "Yes" if size_flag else "No",
            "risk": risk
        }
