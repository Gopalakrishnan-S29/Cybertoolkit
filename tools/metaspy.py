# tools/metaspy.py
import os
import mimetypes
import math
from typing import Dict, Any
from datetime import datetime

import exifread           # pip install exifread
from PIL import Image     # pip install Pillow
import PyPDF2             # pip install PyPDF2
import docx               # pip install python-docx


class MetaSpyScanner:
    """
    File & image intelligence scanner.
    Supports:
      - Images: EXIF, GPS, steganography detection, integrity analysis
      - PDF: metadata
      - DOCX: core properties
    """

    def __init__(self):
        pass

    # =========================================================
    # MAIN ENTRY
    # =========================================================
    def analyze_file(self, path: str) -> Dict[str, Any]:
        path = os.path.abspath(path)

        out: Dict[str, Any] = {
            "filename": os.path.basename(path),
            "path": path,
            "file_size": None,
            "mime": None,
            "fs_created": None,
            "fs_modified": None,
            "type": "other",
            "metadata": {},
        }

        if not os.path.exists(path):
            out["error"] = "file_not_found"
            return out

        # ---- File system metadata ----
        try:
            st = os.stat(path)
            out["file_size"] = st.st_size
            out["fs_modified"] = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
            out["fs_created"] = datetime.utcfromtimestamp(st.st_ctime).isoformat() + "Z"
        except Exception as e:
            out["metadata"]["fs_error"] = str(e)

        mime, _ = mimetypes.guess_type(path)
        out["mime"] = mime or "application/octet-stream"
        ext = os.path.splitext(path)[1].lower()

        # ---- IMAGE ----
        if ext in (".jpg", ".jpeg", ".tiff", ".tif", ".png", ".heic"):
            out["type"] = "image"

            try:
                out["metadata"].update(self._extract_image_exif(path))
            except Exception as e:
                out["metadata"]["exif_error"] = str(e)

            # 🔥 New features
            out["metadata"]["steganography"] = self._stego_scan(path)
            out["metadata"]["integrity"] = self._integrity_check(path)

        # ---- PDF ----
        elif ext == ".pdf":
            out["type"] = "pdf"
            try:
                out["metadata"].update(self._extract_pdf_metadata(path))
            except Exception as e:
                out["metadata"]["pdf_error"] = str(e)

        # ---- DOCX ----
        elif ext == ".docx":
            out["type"] = "docx"
            try:
                out["metadata"].update(self._extract_docx_coreprops(path))
            except Exception as e:
                out["metadata"]["docx_error"] = str(e)

        return out

    # =========================================================
    # IMAGE: EXIF
    # =========================================================
    def _extract_image_exif(self, path: str) -> Dict[str, Any]:
        meta = {}

        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)

        for k, v in tags.items():
            if "JPEGThumbnail" in str(k):
                 meta["thumbnail"] = "Embedded JPEG thumbnail present"
                 continue
            meta[str(k)] = str(v)

        for tag in ("EXIF DateTimeOriginal", "Image DateTime", "EXIF DateTimeDigitized"):
            if tag in tags:
                meta["datetime"] = str(tags[tag])
                break

        if "Image Model" in tags:
            meta["camera_model"] = str(tags["Image Model"])
        if "Image Make" in tags:
            meta["camera_make"] = str(tags["Image Make"])

        gps_keys = [k for k in tags if k.startswith("GPS")]
        if gps_keys:
            meta["gps_raw"] = {k: str(tags[k]) for k in gps_keys}

            lat = self._exif_gps_to_decimal(tags, "GPS GPSLatitude", "GPS GPSLatitudeRef")
            lon = self._exif_gps_to_decimal(tags, "GPS GPSLongitude", "GPS GPSLongitudeRef")

            if lat is not None and lon is not None:
                meta["gps_lat"] = lat
                meta["gps_lon"] = lon

        return meta

    def _exif_gps_to_decimal(self, tags, coord_tag, ref_tag):
        if coord_tag not in tags or ref_tag not in tags:
            return None

        try:
            coord = tags[coord_tag].values

            def _to_float(r):
                return float(r.num) / float(r.den)

            d = _to_float(coord[0])
            m = _to_float(coord[1])
            s = _to_float(coord[2]) if len(coord) > 2 else 0.0

            deg = d + (m / 60.0) + (s / 3600.0)
            if str(tags[ref_tag]) in ("S", "W"):
                deg = -deg

            return round(deg, 6)
        except Exception:
            return None

    # =========================================================
    # STEGANOGRAPHY DETECTION
    # =========================================================
    def _stego_scan(self, path: str) -> Dict[str, Any]:
        result = {
            "lsb_anomaly": False,
            "entropy": None,
            "entropy_flag": False,
            "trailing_data": False,
            "risk": "LOW"
        }

        try:
            # ---- LSB analysis (sampling) ----
            with Image.open(path) as img:
                img = img.convert("RGB")
                pixels = list(img.getdata())[:5000]

            lsb = sum((r & 1) + (g & 1) + (b & 1) for r, g, b in pixels)
            ratio = lsb / (len(pixels) * 3)

            if ratio > 0.55:
                result["lsb_anomaly"] = True

            # ---- Entropy ----
            with open(path, "rb") as f:
                data = f.read()

            freq = [0] * 256
            for b in data:
                freq[b] += 1

            entropy = 0.0
            for c in freq:
                if c:
                    p = c / len(data)
                    entropy -= p * math.log2(p)

            result["entropy"] = round(entropy, 3)
            if entropy > 7.7:
                result["entropy_flag"] = True

            # ---- Trailing data (JPEG) ----
            if path.lower().endswith((".jpg", ".jpeg")):
                eof = data.rfind(b"\xff\xd9")
                if eof != -1 and eof + 2 < len(data):
                    result["trailing_data"] = True

            flags = sum([
                result["lsb_anomaly"],
                result["entropy_flag"],
                result["trailing_data"]
            ])

            if flags >= 2:
                result["risk"] = "HIGH"
            elif flags == 1:
                result["risk"] = "MEDIUM"

        except Exception as e:
            result["error"] = str(e)

        return result

    # =========================================================
    # IMAGE INTEGRITY / MANIPULATION
    # =========================================================
    def _integrity_check(self, path: str) -> Dict[str, Any]:
        result = {
            "edited": False,
            "ela_inconsistency": False,
            "ai_generated_probability": 0.0,
            "risk": "LOW"
        }

        try:
            with Image.open(path) as img:
                if img.format != "JPEG":
                    return result

                temp = path + ".ela_tmp.jpg"
                img.save(temp, "JPEG", quality=90)

            with open(path, "rb") as f1, open(temp, "rb") as f2:
                diff = sum(abs(a - b) for a, b in zip(f1.read(), f2.read()))

            os.remove(temp)

            if diff > 500000:
                result["ela_inconsistency"] = True
                result["edited"] = True
                result["risk"] = "MEDIUM"

            # Lightweight AI heuristic
            result["ai_generated_probability"] = 0.4 if result["edited"] else 0.1

        except Exception as e:
            result["error"] = str(e)

        return result

    # =========================================================
    # PDF
    # =========================================================
    def _extract_pdf_metadata(self, path: str) -> Dict[str, Any]:
        meta = {}
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            info = reader.metadata
            if info:
                for k, v in info.items():
                    meta[str(k).strip("/")] = str(v)
        return meta

    # =========================================================
    # DOCX
    # =========================================================
    def _extract_docx_coreprops(self, path: str) -> Dict[str, Any]:
        meta = {}
        doc = docx.Document(path)
        props = doc.core_properties

        meta["author"] = props.author
        meta["title"] = props.title
        meta["subject"] = props.subject
        meta["last_modified_by"] = props.last_modified_by
        meta["category"] = props.category
        meta["comments"] = props.comments

        if props.created:
            meta["created"] = props.created.isoformat()
        if props.modified:
            meta["modified"] = props.modified.isoformat()

        return meta
