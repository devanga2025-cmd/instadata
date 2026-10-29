import re

from .misuse_mapper import possible_misuse_for
from .risk_calculator import RISK_WEIGHTS, calculate_score, severity_for_detection

try:
    import spacy
except ImportError:
    spacy = None

_NLP = None


def _get_nlp():
    global _NLP
    if spacy is None:
        return None
    if _NLP is None:
        try:
            _NLP = spacy.load("en_core_web_sm")
        except OSError:
            _NLP = False
    return _NLP if _NLP is not False else None


REGEX_PATTERNS = {
    "Phone Number": re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"),
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "Personal ID": re.compile(
        r"\b(?:\d{4}[\s-]?\d{4}[\s-]?\d{4}|[A-Z]{5}\d{4}[A-Z]|\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b",
        re.IGNORECASE,
    ),
    "IP Address": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "Date of Birth": re.compile(r"\b(?:dob|date of birth|born on|birthday)\s*(?:is|:)?\s*([0-3]?\d[\s/-][01]?\d[\s/-](?:19|20)\d{2})\b", re.IGNORECASE),
    "Password / OTP": re.compile(r"\b(?:otp|password|passcode|pin)\s*(?:is|:)?\s*([A-Za-z0-9@#$%^&*!-]{4,})\b", re.IGNORECASE),
    "Bank Information": re.compile(r"\b(?:account number|ifsc|cvv|card number|upi)\s*(?:is|:)?\s*([A-Za-z0-9\s-]{4,})\b", re.IGNORECASE),
    "Vehicle Registration Number": re.compile(r"\b[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{4}\b", re.IGNORECASE),
    "Travel Ticket / Booking Information": re.compile(r"\b(?:pnr|booking id|ticket number|flight|train)\s*(?:is|:)?\s*([A-Z0-9-]{5,})\b", re.IGNORECASE),
}

CONTEXT_PATTERNS = {
    "Home Address": re.compile(r"\b(?:my address is|home address is|address is|I live at|house is)\s+([^.\n,]+(?:[, ]+[A-Za-z][A-Za-z\s]+)?)", re.IGNORECASE),
    "Travel Plan": re.compile(r"\b(?:tomorrow|today|next week|next month|tonight|on vacation|going to|travelling to|traveling to|leaving for)\b[^.\n]*", re.IGNORECASE),
    "Current Location": re.compile(r"\b(?:I am at|I'm at|currently at|right now at|my current location is)\s+([^.\n]+)", re.IGNORECASE),
    "Home Unattended Information": re.compile(r"\b(?:nobody will be home|no one will be home|home alone|house is empty|home is empty|away for \d+ days)\b", re.IGNORECASE),
    "Workplace": re.compile(r"\b(?:I work at|working at|my office is|employed at)\s+([^.\n]+)", re.IGNORECASE),
    "College": re.compile(r"\b(?:I study at|studying at|my college is|student at)\s+([^.\n]+)", re.IGNORECASE),
}


def mask_value(value):
    cleaned = value.strip()
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    visible_start = 2
    visible_end = 2
    return f"{cleaned[:visible_start]}{'*' * max(len(cleaned) - visible_start - visible_end, 3)}{cleaned[-visible_end:]}"


def _recommendation(risk_type):
    recommendations = {
        "Phone Number": "Remove your phone number or share it privately.",
        "Email": "Remove your email address from the public post.",
        "Date of Birth": "Avoid sharing your date of birth publicly.",
        "Location": "Avoid sharing exact locations publicly.",
        "Current Location": "Post current locations after you leave, or remove them.",
        "Travel Plan": "Avoid sharing exact travel plans publicly.",
        "Home Unattended Information": "Remove details that show your home is unattended.",
        "Home Address": "Remove your exact home address.",
        "Personal ID": "Remove Aadhaar, PAN, card, or other ID numbers.",
        "Bank Information": "Remove bank, card, CVV, IFSC, or UPI details.",
        "Password / OTP": "Never post passwords, OTPs, PINs, or passcodes.",
        "Person Name": "Avoid naming private people without permission.",
        "Workplace": "Avoid sharing workplace details publicly.",
        "College": "Avoid sharing college details publicly.",
        "IP Address": "Remove IP addresses from public posts.",
        "Vehicle Registration Number": "Your vehicle registration number is visible. Consider blurring the number plate before posting.",
        "Travel Ticket / Booking Information": "Remove ticket, booking, PNR, flight, or train details before posting.",
    }
    return recommendations.get(risk_type, "Remove or generalize this information.")


def _build_detection(risk_type, value, source="text"):
    weight = RISK_WEIGHTS[risk_type]
    return {
        "risk_type": risk_type,
        "masked_value": mask_value(value),
        "severity": severity_for_detection(risk_type, weight),
        "risk_weight": weight,
        "recommendation": _recommendation(risk_type),
        "source": source,
    }


def detect_text_privacy(text, source="text"):
    detections = []
    seen = set()

    for risk_type, pattern in REGEX_PATTERNS.items():
        for match in pattern.finditer(text or ""):
            value = match.group(1) if match.groups() else match.group(0)
            key = (risk_type, value.lower())
            if key not in seen:
                detections.append(_build_detection(risk_type, value, source))
                seen.add(key)

    for risk_type, pattern in CONTEXT_PATTERNS.items():
        for match in pattern.finditer(text or ""):
            value = match.group(1) if match.groups() else match.group(0)
            key = (risk_type, value.lower())
            if key not in seen:
                detections.append(_build_detection(risk_type, value, source))
                seen.add(key)

    nlp = _get_nlp()
    if nlp:
        doc = nlp(text or "")
        for ent in doc.ents:
            risk_type = None
            if ent.label_ == "PERSON":
                risk_type = "Person Name"
            elif ent.label_ in {"GPE", "LOC", "FAC"}:
                risk_type = "Location"
            if risk_type:
                key = (risk_type, ent.text.lower())
                if key not in seen:
                    detections.append(_build_detection(risk_type, ent.text, source))
                    seen.add(key)

    score, level = calculate_score(detections)
    return {
        "risk_score": score,
        "risk_level": level,
        "detections": detections,
        "possible_misuse": possible_misuse_for([item["risk_type"] for item in detections]),
    }


def remove_sensitive_text(text):
    cleaned = text or ""
    for pattern in REGEX_PATTERNS.values():
        cleaned = pattern.sub("[removed]", cleaned)
    for pattern in CONTEXT_PATTERNS.values():
        cleaned = pattern.sub("[removed]", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()
