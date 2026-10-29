MISUSE_BY_RISK_TYPE = {
    "Phone Number": ["Phishing", "Social Engineering", "Cyberstalking"],
    "Email": ["Phishing", "Identity Theft", "Social Engineering"],
    "Date of Birth": ["Identity Theft", "Account Recovery Abuse"],
    "Location": ["Cyberstalking", "Physical Security Risk"],
    "Current Location": ["Cyberstalking", "Physical Security Risk"],
    "Travel Plan": ["Physical Security Risk", "Cyberstalking"],
    "Home Unattended Information": ["Physical Security Risk", "Burglary Risk"],
    "Home Address": ["Physical Security Risk", "Cyberstalking", "Identity Theft"],
    "Personal ID": ["Identity Theft", "Financial Fraud"],
    "Bank Information": ["Financial Fraud", "Identity Theft"],
    "Password / OTP": ["Account Takeover", "Financial Fraud"],
    "Person Name": ["Identity Theft", "Impersonation"],
    "Workplace": ["Social Engineering", "Impersonation"],
    "College": ["Social Engineering", "Impersonation"],
    "IP Address": ["Cyberstalking", "Technical Targeting"],
    "Vehicle Registration Number": ["Vehicle identification", "Identity/location profiling", "Unwanted tracking"],
    "Travel Ticket / Booking Information": ["Identity Theft", "Physical Security Risk", "Travel Fraud"],
    "ID Card": ["Identity Theft", "Impersonation"],
    "Bank Card": ["Financial Fraud", "Identity Theft"],
    "Travel Ticket": ["Travel Fraud", "Identity Theft"],
    "QR Code": ["Phishing", "Account Takeover"],
    "GPS Location Metadata": ["Cyberstalking", "Physical Security Risk"],
}


def possible_misuse_for(risk_types):
    misuse = []
    for risk_type in risk_types:
        for item in MISUSE_BY_RISK_TYPE.get(risk_type, []):
            if item not in misuse:
                misuse.append(item)
    return misuse
