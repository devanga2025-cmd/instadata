RISK_WEIGHTS = {
    "Phone Number": 20,
    "Email": 10,
    "Date of Birth": 15,
    "Location": 20,
    "Current Location": 20,
    "Travel Plan": 20,
    "Home Unattended Information": 25,
    "Home Address": 30,
    "Personal ID": 35,
    "Bank Information": 40,
    "Password / OTP": 40,
    "Person Name": 5,
    "Workplace": 15,
    "College": 15,
    "IP Address": 20,
    "Vehicle Registration Number": 45,
    "Travel Ticket / Booking Information": 30,
    "ID Card": 35,
    "Bank Card": 40,
    "Travel Ticket": 30,
    "QR Code": 25,
    "GPS Location Metadata": 30,
}

CRITICAL_RISK_TYPES = {"Personal ID", "Bank Information", "Password / OTP", "ID Card", "Bank Card"}

SEVERITY_BY_WEIGHT = (
    (35, "CRITICAL"),
    (25, "CRITICAL"),
    (20, "HIGH"),
    (15, "MEDIUM"),
    (10, "LOW"),
    (0, "LOW"),
)


def severity_for_weight(weight):
    for minimum, severity in SEVERITY_BY_WEIGHT:
        if weight >= minimum:
            return severity
    return "LOW"


def severity_for_detection(risk_type, weight):
    if risk_type == "Vehicle Registration Number":
        return "MEDIUM"
    if risk_type in CRITICAL_RISK_TYPES:
        return "CRITICAL"
    return severity_for_weight(weight)


def level_for_score(score):
    if score <= 0:
        return "SAFE"
    if score <= 20:
        return "LOW"
    if score <= 40:
        return "MEDIUM"
    if score <= 60:
        return "HIGH"
    return "CRITICAL"


def calculate_score(detections):
    total = sum(item["risk_weight"] for item in detections)
    score = min(total, 100)
    if any(item["risk_type"] in CRITICAL_RISK_TYPES for item in detections):
        score = max(score, 81)
    return score, level_for_score(score)
