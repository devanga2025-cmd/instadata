import re
import ssl

from django.core.files.base import ContentFile
from django.conf import settings

from .text_detector import detect_text_privacy

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import easyocr
except ImportError:
    easyocr = None

try:
    import certifi
except ImportError:
    certifi = None

try:
    from PIL import Image, ImageOps, ExifTags
except ImportError:
    Image = None
    ImageOps = None
    ExifTags = None


_READER = None
_OCR_FAILED = False
VEHICLE_PLATE_PATTERN = re.compile(r"\b[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{4}\b", re.IGNORECASE)
ID_KEYWORDS = re.compile(r"\b(?:aadhaar|aadhar|pan|passport|driving\s+licen[cs]e|voter\s+id)\b", re.IGNORECASE)
CARD_KEYWORDS = re.compile(r"\b(?:debit|credit|card\s+number|cvv|valid\s+thru|valid\s+until)\b", re.IGNORECASE)
TICKET_KEYWORDS = re.compile(r"\b(?:boarding\s+pass|pnr|booking\s*(?:id|reference)|ticket\s*(?:number|no)|flight|train)\b", re.IGNORECASE)


def _get_reader():
    global _READER
    if easyocr is None:
        return None
    if _READER is None:
        try:
            if certifi is not None:
                ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())
            _READER = easyocr.Reader(
                ["en"],
                gpu=False,
                model_storage_directory=str(settings.BASE_DIR / ".easyocr_models"),
                verbose=False,
            )
        except Exception:
            _READER = False
    return _READER if _READER is not False else None


def _decode_image(image_file):
    if not image_file or cv2 is None:
        return None
    try:
        image_file.seek(0)
        data = image_file.read()
        image_file.seek(0)
        import numpy as np
        # PIL applies EXIF orientation so the pixels OCR sees match the photo
        # orientation users see on their device.
        if Image is not None and ImageOps is not None:
            with Image.open(__import__('io').BytesIO(data)) as source:
                oriented = ImageOps.exif_transpose(source).convert("RGB")
                return cv2.cvtColor(np.asarray(oriented), cv2.COLOR_RGB2BGR)
        return cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    except Exception:
        return None


def _ocr_variants(image):
    """Return complementary OCR inputs; one threshold often erases faint text."""
    height, width = image.shape[:2]
    scale = min(2.0, 1800 / max(height, width)) if max(height, width) < 1800 else 1.0
    if scale > 1:
        image = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    _, otsu = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    adaptive = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 11)
    # Keep inverse variants for dark backgrounds; EasyOCR handles both.
    return [(variant, scale) for variant in (gray, otsu, 255 - otsu, adaptive)]


def extract_ocr_results(image_file):
    global _OCR_FAILED
    _OCR_FAILED = False
    if not image_file or cv2 is None or easyocr is None:
        _OCR_FAILED = True
        return []
    try:
        image = _decode_image(image_file)
        reader = _get_reader() if image is not None else None
        if not reader:
            _OCR_FAILED = True
            return []
        results = []
        for variant, scale in _ocr_variants(image):
            for box, text, confidence in reader.readtext(variant, detail=1, paragraph=False):
                text = (text or "").strip()
                if not text or confidence < 0.20:
                    continue
                original_box = [[int(round(x / scale)), int(round(y / scale))] for x, y in box]
                candidate = (original_box, text, float(confidence))
                # Multiple preprocessing passes commonly return the same word.
                if not any(_same_ocr_result(candidate, existing) for existing in results):
                    results.append(candidate)
                else:
                    for index, existing in enumerate(results):
                        if _same_ocr_result(candidate, existing) and confidence > existing[2]:
                            results[index] = candidate
                            break
        return results
    except Exception:
        _OCR_FAILED = True
        return []


def _same_ocr_result(first, second):
    if _normalize_plate_text(first[1]) != _normalize_plate_text(second[1]):
        return False
    a, b = _box_to_region(first[0]), _box_to_region(second[0])
    left, top = max(a[0], b[0]), max(a[1], b[1])
    right, bottom = min(a[2], b[2]), min(a[3], b[3])
    intersection = max(0, right - left) * max(0, bottom - top)
    area_a = max(1, (a[2] - a[0]) * (a[3] - a[1]))
    area_b = max(1, (b[2] - b[0]) * (b[3] - b[1]))
    return intersection / min(area_a, area_b) >= 0.5


def _box_to_region(box):
    xs = [int(point[0]) for point in box]
    ys = [int(point[1]) for point in box]
    return (min(xs), min(ys), max(xs), max(ys))


def _normalize_plate_text(text):
    return re.sub(r"[^A-Z0-9]", "", (text or "").upper())


def _looks_like_vehicle_plate(text):
    compact = _normalize_plate_text(text)
    return bool(VEHICLE_PLATE_PATTERN.search(text or "") or re.fullmatch(r"[A-Z]{2}\d{1,2}[A-Z]{1,3}\d{4}", compact))


def _image_detection(risk_type, value, weight, recommendation, region=None):
    masked = value if value in {"EXIF GPS metadata", "QR code", "ID card", "Bank card", "Travel ticket"} else _mask(value)
    return {
        "risk_type": risk_type,
        "masked_value": masked,
        "severity": "CRITICAL" if weight >= 35 else "HIGH" if weight >= 20 else "LOW",
        "risk_weight": weight,
        "recommendation": recommendation,
        "source": "image",
        "region": region,
    }


def _mask(value):
    value = (value or "").strip()
    return value[:2] + "*" * max(3, len(value) - 4) + value[-2:] if len(value) > 4 else "*" * len(value)


def _detect_metadata(image_file):
    if not image_file or Image is None:
        return []
    try:
        image_file.seek(0)
        image = Image.open(image_file)
        exif = image.getexif()
        image_file.seek(0)
        gps_tag = next((key for key, name in ExifTags.TAGS.items() if name == "GPSInfo"), None)
        if gps_tag is not None and exif.get(gps_tag):
            return [_image_detection("GPS Location Metadata", "EXIF GPS metadata", 30, "GPS coordinates are embedded in this image. Remove metadata before posting.")]
    except Exception:
        pass
    return []


def _detect_qr_codes(image):
    if image is None or cv2 is None:
        return []
    try:
        detector = cv2.QRCodeDetector()
        found, decoded, points, _ = detector.detectAndDecodeMulti(image)
        if not found or points is None:
            return []
        return [_image_detection("QR Code", "QR code", 25, "A QR code can reveal private links or account details. Mask it before posting.", _box_to_region(box)) for box in points]
    except Exception:
        return []


def _detect_plate_shaped_regions(image):
    """OpenCV fallback for plates that OCR cannot read because of glare or distance."""
    if image is None or cv2 is None:
        return []
    try:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        blackhat = cv2.morphologyEx(gray, cv2.MORPH_BLACKHAT, cv2.getStructuringElement(cv2.MORPH_RECT, (13, 5)))
        gradient = cv2.Sobel(blackhat, cv2.CV_32F, 1, 0, ksize=-1)
        gradient = cv2.convertScaleAbs(gradient)
        _, threshold = cv2.threshold(gradient, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        threshold = cv2.morphologyEx(threshold, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_RECT, (17, 5)))
        contours, _ = cv2.findContours(threshold, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        candidates = []
        image_area = image.shape[0] * image.shape[1]
        for contour in contours:
            x, y, width, height = cv2.boundingRect(contour)
            ratio = width / max(height, 1)
            area = width * height
            if 2.0 <= ratio <= 6.5 and image_area * 0.0003 <= area <= image_area * 0.08 and width >= 55 and height >= 12:
                candidates.append(_image_detection(
                    "Vehicle Registration Number",
                    "plate-like region",
                    45,
                    "A vehicle number plate may be visible. Protect the image before posting.",
                    (x, y, x + width, y + height),
                ))
        return sorted(candidates, key=lambda item: (item["region"][2] - item["region"][0]) * (item["region"][3] - item["region"][1]), reverse=True)[:2]
    except Exception:
        return []


def _detect_ocr_privacy(ocr_results):
    detections = []

    def add_once(detection):
        if not any(
            existing["risk_type"] == detection["risk_type"]
            and existing["masked_value"] == detection["masked_value"]
            and _regions_overlap(existing.get("region"), detection.get("region"))
            for existing in detections
        ):
            detections.append(detection)

    for box, text, confidence in ocr_results:
        # Low-confidence snippets create noisy detections; retain OCR-derived
        # sensitive findings only when the recognized token is reasonably clear.
        if confidence < 0.30:
            continue
        region = _box_to_region(box)
        result = detect_text_privacy(text, source="image")
        for item in result["detections"]:
            item["region"] = region
            add_once(item)
        if _looks_like_vehicle_plate(text):
            plate = _image_detection("Vehicle Registration Number", _normalize_plate_text(text), 45, "Your vehicle registration number is visible. Protect the image before posting.", region)
            add_once(plate)
        if ID_KEYWORDS.search(text):
            add_once(_image_detection("ID Card", "ID card", 35, "An identity document may be visible. Mask it before posting.", region))
        if CARD_KEYWORDS.search(text):
            add_once(_image_detection("Bank Card", "Bank card", 40, "Bank card details may be visible. Mask them before posting.", region))
        if TICKET_KEYWORDS.search(text):
            add_once(_image_detection("Travel Ticket", "Travel ticket", 30, "Ticket details can expose booking information. Mask them before posting.", region))
    return detections


def _regions_overlap(first, second):
    if not first or not second:
        return first == second
    left, top = max(first[0], second[0]), max(first[1], second[1])
    right, bottom = min(first[2], second[2]), min(first[3], second[3])
    intersection = max(0, right - left) * max(0, bottom - top)
    area_first = max(1, (first[2] - first[0]) * (first[3] - first[1]))
    area_second = max(1, (second[2] - second[0]) * (second[3] - second[1]))
    return intersection / min(area_first, area_second) >= 0.5


def detect_image_privacy(image_file):
    image = _decode_image(image_file)
    ocr_results = extract_ocr_results(image_file)
    detections = _detect_ocr_privacy(ocr_results) + _detect_qr_codes(image) + _detect_metadata(image_file)
    if image is None or _OCR_FAILED:
        detections.append(_image_detection(
            "Image analysis unavailable", "OCR could not be initialized", 25,
            "Automatic image analysis could not complete. Check the server OCR/image setup, or review this image manually.",
        ))
    # A generic elongated rectangle is far too common in text-heavy photos;
    # treating one as a plate caused ordinary phone numbers and captions to
    # become false vehicle-plate alerts. Plate findings now require OCR text
    # to match the registration pattern above.
    from .misuse_mapper import possible_misuse_for
    from .risk_calculator import calculate_score
    score, level = calculate_score(detections)
    return {"risk_score": score, "risk_level": level, "detections": detections, "possible_misuse": possible_misuse_for([item["risk_type"] for item in detections])}


def protect_image_privacy(image_file):
    """Mask detected image regions and re-encode the image without EXIF metadata."""
    image = _decode_image(image_file)
    if image is None or cv2 is None:
        return None
    scan_result = detect_image_privacy(image_file)
    for detection in scan_result["detections"]:
        region = detection.get("region")
        if not region:
            continue
        x1, y1, x2, y2 = region
        padding = 8
        x1, y1 = max(0, x1 - padding), max(0, y1 - padding)
        x2, y2 = min(image.shape[1], x2 + padding), min(image.shape[0], y2 + padding)
        if x2 > x1 and y2 > y1:
            image[y1:y2, x1:x2] = cv2.GaussianBlur(image[y1:y2, x1:x2], (51, 51), 0)
    ok, encoded = cv2.imencode(".jpg", image)
    return ContentFile(encoded.tobytes()) if ok else None


def blur_vehicle_number_plates(image_file):
    return protect_image_privacy(image_file)
