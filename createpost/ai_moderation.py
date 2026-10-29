import base64
import io
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.core.files.storage import default_storage

try:
    import cv2
except ImportError:
    cv2 = None

try:
    from PIL import Image, ImageOps
except ImportError:
    Image = None
    ImageOps = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from privacy_engine.services.image_detector import detect_image_privacy
from privacy_engine.services.misuse_mapper import possible_misuse_for
from privacy_engine.services.text_detector import detect_text_privacy

_CLIENT = None


def get_openai_client():
    """Lazily initialize the OpenAI client."""
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return None
    try:
        _CLIENT = OpenAI(api_key=api_key)
        return _CLIENT
    except Exception:
        return None


# =====================================================================
# Category Definitions & Mapping
# Groups: Harmful, Explicit, Violent, Sensitive, Inappropriate
# =====================================================================

CATEGORY_CONFIG = {
    # Explicit Content
    "sexual": {
        "group": "Explicit",
        "label": "Explicit / Adult Content",
        "description": "Sexually explicit content, nudity, or adult material detected.",
        "default_severity": "HIGH",
        "recommendation": "Remove explicit or NSFW media before sharing publicly.",
    },
    "sexual_minors": {
        "group": "Explicit",
        "label": "Severe Explicit Content",
        "description": "Prohibited explicit content involving minors detected.",
        "default_severity": "CRITICAL",
        "recommendation": "This content is strictly illegal and blocked across the platform.",
    },
    # Violent Content
    "violence": {
        "group": "Violent",
        "label": "Violent Content",
        "description": "Depiction of physical violence, assault, or weapons detected.",
        "default_severity": "HIGH",
        "recommendation": "Remove violent imagery or aggressive language before posting.",
    },
    "violence_graphic": {
        "group": "Violent",
        "label": "Graphic Violence & Gore",
        "description": "Severe graphic violence, bodily mutilation, blood, or gore detected.",
        "default_severity": "CRITICAL",
        "recommendation": "Graphic violence violates community safety and is strictly blocked.",
    },
    "illicit_violent": {
        "group": "Violent",
        "label": "Violent Criminal Activity",
        "description": "Depiction or promotion of violent unlawful actions detected.",
        "default_severity": "CRITICAL",
        "recommendation": "Do not post violent criminal or threatening material.",
    },
    # Harmful Content
    "hate": {
        "group": "Harmful",
        "label": "Hate Speech",
        "description": "Hate speech, discrimination, or derogatory slurs detected.",
        "default_severity": "HIGH",
        "recommendation": "Maintain a respectful community by removing hateful statements.",
    },
    "hate_threatening": {
        "group": "Harmful",
        "label": "Threatening Hate Speech",
        "description": "Threats of physical harm based on protected characteristics detected.",
        "default_severity": "CRITICAL",
        "recommendation": "Hateful threats are zero-tolerance and blocked immediately.",
    },
    "harassment": {
        "group": "Harmful",
        "label": "Harassment / Abuse",
        "description": "Abusive, hostile, or intimidating statements detected.",
        "default_severity": "MEDIUM",
        "recommendation": "Revise the post to avoid targeted harassment or abuse.",
    },
    "harassment_threatening": {
        "group": "Harmful",
        "label": "Threatening Harassment",
        "description": "Direct threats of harm, stalking, or intimidation detected.",
        "default_severity": "HIGH",
        "recommendation": "Remove threatening remarks before publishing.",
    },
    "self_harm": {
        "group": "Harmful",
        "label": "Self-Harm Content",
        "description": "Content depicting, promoting, or glorifying self-harm or suicide.",
        "default_severity": "CRITICAL",
        "recommendation": "Content related to self-harm is blocked for user safety and wellness.",
    },
    "self_harm_intent": {
        "group": "Harmful",
        "label": "Self-Harm Intent",
        "description": "Statements indicating intent of suicide or self-harm detected.",
        "default_severity": "CRITICAL",
        "recommendation": "If you or someone you know is in crisis, please reach out to a support helpline.",
    },
    "self_harm_instructions": {
        "group": "Harmful",
        "label": "Self-Harm Instructions",
        "description": "Instructions or guidance on methods of self-harm or suicide.",
        "default_severity": "CRITICAL",
        "recommendation": "Self-harm instructions are strictly blocked.",
    },
    # Inappropriate Content
    "illicit": {
        "group": "Inappropriate",
        "label": "Illicit / Prohibited Goods or Activities",
        "description": "Content involving illegal substances, weapons trade, or illicit acts.",
        "default_severity": "HIGH",
        "recommendation": "Do not share content promoting illegal activities or contraband.",
    },
}

# Heuristic patterns for offline / fallback checks
HEURISTIC_PATTERNS = [
    (re.compile(r"\b(?:kill\s+yourself|commit\s+suicide|end\s+my\s+life|hang\s+myself)\b", re.I), "self_harm", "CRITICAL"),
    (re.compile(r"\b(?:i\s+will\s+kill\s+you|gonna\s+murder|die\s+bitch|slit\s+your\s+throat)\b", re.I), "violence", "CRITICAL"),
    (re.compile(r"\b(?:bomb\s+threat|massacre|terrorist|blow\s+up)\b", re.I), "violence", "HIGH"),
    (re.compile(r"\b(?:nude|porn|xxx|nsfw|sex\s+video|naked)\b", re.I), "sexual", "HIGH"),
    (re.compile(r"\b(?:fuck\s+you|asshole|bastard|bitch|faggot|nigger|retard)\b", re.I), "harassment", "MEDIUM"),
]


def _normalize_category_key(key):
    """Normalize OpenAI category keys (replace slashes and dashes with underscores)."""
    return key.replace("/", "_").replace("-", "_")


def _run_openai_moderation(input_payload):
    """
    Execute OpenAI omni-moderation-latest on input (string or image list).
    Returns (flagged, category_scores_dict, categories_flagged_dict) or None on failure.
    """
    client = get_openai_client()
    if not client:
        return None
    try:
        response = client.moderations.create(
            model="omni-moderation-latest",
            input=input_payload,
        )
        result = response.results[0]
        categories = {_normalize_category_key(k): v for k, v in result.categories.model_dump().items()}
        scores = {_normalize_category_key(k): float(v) for k, v in result.category_scores.model_dump().items()}
        return result.flagged, scores, categories
    except Exception:
        return None


def _fallback_text_moderation(text):
    """Heuristic fallback when OpenAI API is unavailable or offline."""
    detected = []
    max_score = 0
    flagged = False
    for pattern, category_key, severity in HEURISTIC_PATTERNS:
        if pattern.search(text):
            flagged = True
            config = CATEGORY_CONFIG.get(category_key, {})
            score = 90 if severity == "CRITICAL" else 75
            max_score = max(max_score, score)
            detected.append({
                "group": config.get("group", "Harmful"),
                "risk_type": config.get("label", category_key.title()),
                "category_key": category_key,
                "severity": severity,
                "score": score,
                "risk_weight": 35 if severity == "CRITICAL" else 25,
                "description": config.get("description", "Inappropriate content detected."),
                "masked_value": "[DETECTED BY HEURISTIC FILTER]",
                "recommendation": config.get("recommendation", "Review and remove sensitive content."),
                "source": "text",
            })
    return flagged, max_score, detected


# =====================================================================
# Text Moderation
# =====================================================================

def moderate_text(text):
    """
    Analyzes text (caption, location, activity) for:
    - Harmful, explicit, violent, and inappropriate content (AI Moderation)
    - Sensitive personal information (PII detector)
    Returns: dict with risk_score, issues, pii_detections, flagged
    """
    if not text or not text.strip():
        return {
            "flagged": False,
            "risk_score": 0,
            "category_scores": {},
            "issues": [],
            "pii_detections": [],
        }

    issues = []
    ai_risk_score = 0
    flagged = False

    # 1. AI Content Moderation (Harmful, Explicit, Violent, Inappropriate)
    openai_result = _run_openai_moderation(text)
    if openai_result:
        flagged, scores, categories = openai_result
        for cat_key, config in CATEGORY_CONFIG.items():
            score = scores.get(cat_key, 0.0)
            is_cat_flagged = categories.get(cat_key, False)
            # Threshold: flagged by OpenAI or score >= 0.30
            if is_cat_flagged or score >= 0.30:
                cat_score_100 = round(score * 100)
                if is_cat_flagged and cat_score_100 < 70:
                    cat_score_100 = 70
                severity = "CRITICAL" if cat_score_100 >= 90 or config["default_severity"] == "CRITICAL" else (
                    "HIGH" if cat_score_100 >= 70 or config["default_severity"] == "HIGH" else "MEDIUM"
                )
                ai_risk_score = max(ai_risk_score, cat_score_100)
                issues.append({
                    "group": config["group"],
                    "risk_type": config["label"],
                    "category_key": cat_key,
                    "severity": severity,
                    "score": cat_score_100,
                    "risk_weight": cat_score_100,
                    "description": config["description"],
                    "masked_value": f"{config['label']} (Confidence: {cat_score_100}%)",
                    "recommendation": config["recommendation"],
                    "source": "text",
                })
    else:
        # Offline Heuristic Fallback
        flagged, ai_risk_score, issues = _fallback_text_moderation(text)

    # 2. Sensitive Personal Information (PII) Check
    pii_result = detect_text_privacy(text)
    pii_detections = []
    for item in pii_result.get("detections", []):
        pii_detections.append({
            "group": "Sensitive",
            "risk_type": item["risk_type"],
            "category_key": "sensitive_pii",
            "severity": item.get("severity", "MEDIUM"),
            "score": item.get("risk_weight", 20),
            "risk_weight": item.get("risk_weight", 20),
            "description": f"Personal sensitive information found: {item['risk_type']}.",
            "masked_value": item.get("masked_value", "[REDACTED]"),
            "recommendation": item.get("recommendation", "Remove personal identifying information."),
            "source": "text",
        })

    return {
        "flagged": flagged or bool(issues),
        "risk_score": ai_risk_score,
        "issues": issues,
        "pii_detections": pii_detections,
    }


# =====================================================================
# Image Moderation
# =====================================================================

def _prepare_image_for_moderation(image_file_or_data):
    """Ensure image is JPEG base64 and within reasonable dimensions."""
    if Image is None:
        return None
    try:
        if hasattr(image_file_or_data, "seek"):
            image_file_or_data.seek(0)
            img = Image.open(image_file_or_data)
        elif isinstance(image_file_or_data, (bytes, bytearray)):
            img = Image.open(io.BytesIO(image_file_or_data))
        elif isinstance(image_file_or_data, Image.Image):
            img = image_file_or_data
        else:
            return None

        if ImageOps is not None:
            try:
                img = ImageOps.exif_transpose(img)
            except Exception:
                pass

        img = img.convert("RGB")
        # Resize to max 640px to ensure fast upload and processing
        max_dim = 640
        if max(img.width, img.height) > max_dim:
            img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return f"data:image/jpeg;base64,{b64}"
    except Exception:
        return None


def moderate_image(image_file):
    """
    Analyzes an uploaded image for:
    - Harmful, explicit, violent visuals via OpenAI omni-moderation
    - Sensitive PII / QR codes / GPS EXIF metadata via OCR privacy detector
    Returns: dict with risk_score, issues, pii_detections, flagged
    """
    if not image_file:
        return {
            "flagged": False,
            "risk_score": 0,
            "issues": [],
            "pii_detections": [],
        }

    issues = []
    ai_risk_score = 0
    flagged = False

    # 1. AI Visual Moderation (OpenAI omni-moderation)
    image_url = _prepare_image_for_moderation(image_file)
    if image_url:
        payload = [{"type": "image_url", "image_url": {"url": image_url}}]
        openai_result = _run_openai_moderation(payload)
        if openai_result:
            flagged, scores, categories = openai_result
            for cat_key, config in CATEGORY_CONFIG.items():
                score = scores.get(cat_key, 0.0)
                is_cat_flagged = categories.get(cat_key, False)
                if is_cat_flagged or score >= 0.30:
                    cat_score_100 = round(score * 100)
                    if is_cat_flagged and cat_score_100 < 70:
                        cat_score_100 = 70
                    severity = "CRITICAL" if cat_score_100 >= 90 or config["default_severity"] == "CRITICAL" else (
                        "HIGH" if cat_score_100 >= 70 or config["default_severity"] == "HIGH" else "MEDIUM"
                    )
                    ai_risk_score = max(ai_risk_score, cat_score_100)
                    issues.append({
                        "group": config["group"],
                        "risk_type": f"{config['label']} in Image",
                        "category_key": cat_key,
                        "severity": severity,
                        "score": cat_score_100,
                        "risk_weight": cat_score_100,
                        "description": f"Visual detected: {config['description']}",
                        "masked_value": f"Image Finding: {config['label']} ({cat_score_100}%)",
                        "recommendation": config["recommendation"],
                        "source": "image",
                    })

    # 2. Sensitive Personal Information (OCR, GPS, QR)
    pii_detections = []
    try:
        image_pii = detect_image_privacy(image_file)
        for item in image_pii.get("detections", []):
            if item.get("risk_type") == "Image analysis unavailable":
                continue
            pii_detections.append({
                "group": "Sensitive",
                "risk_type": item["risk_type"],
                "category_key": "sensitive_visual",
                "severity": item.get("severity", "MEDIUM"),
                "score": item.get("risk_weight", 25),
                "risk_weight": item.get("risk_weight", 25),
                "description": f"Sensitive detail found in image: {item['risk_type']}.",
                "masked_value": item.get("masked_value", "[Image Region]"),
                "recommendation": item.get("recommendation", "Use 'Protect Image' to mask sensitive areas."),
                "source": "image",
            })
    except Exception:
        pass

    return {
        "flagged": flagged or bool(issues),
        "risk_score": ai_risk_score,
        "issues": issues,
        "pii_detections": pii_detections,
    }


# =====================================================================
# Video Moderation
# Analyzes key representative video frames across duration
# =====================================================================

def _extract_video_frames(video_file_or_path, max_frames=5):
    """
    Extracts representative frames from a video using OpenCV.
    Returns: list of tuples (time_str, frame_rgb_image)
    """
    if cv2 is None or Image is None:
        return []

    temp_path = None
    cap = None
    frames_extracted = []

    try:
        # Determine accessible filesystem path
        if isinstance(video_file_or_path, str):
            if os.path.exists(video_file_or_path):
                source_path = video_file_or_path
            else:
                try:
                    source_path = default_storage.path(video_file_or_path)
                except Exception:
                    temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
                    with default_storage.open(video_file_or_path, "rb") as f:
                        temp_file.write(f.read())
                    temp_file.close()
                    temp_path = temp_file.name
                    source_path = temp_path
        elif hasattr(video_file_or_path, "read"):
            video_file_or_path.seek(0)
            temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
            temp_file.write(video_file_or_path.read())
            temp_file.close()
            temp_path = temp_file.name
            source_path = temp_path
        else:
            return []

        cap = cv2.VideoCapture(source_path)
        if not cap.isOpened():
            return []

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        if total_frames <= 0:
            return []

        # Select evenly distributed sample points
        if total_frames <= max_frames:
            sample_indices = list(range(total_frames))
        else:
            pct_steps = [0.10, 0.30, 0.50, 0.70, 0.90][:max_frames]
            sample_indices = [int(total_frames * p) for p in pct_steps]

        for idx in sample_indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ret, frame = cap.read()
            if not ret or frame is None:
                continue

            sec = int(idx / fps)
            time_str = f"{sec // 60:02d}:{sec % 60:02d}"

            # Convert BGR (OpenCV) to RGB (PIL)
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(rgb)
            frames_extracted.append((time_str, pil_img))

    except Exception:
        pass
    finally:
        if cap is not None:
            cap.release()
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

    return frames_extracted


def moderate_video(video_file_or_path, max_frames=5):
    """
    Extracts representative frames from video and analyzes each for:
    - Harmful, explicit, violent content per frame
    - Sensitive OCR text visible on screen
    Returns: dict with risk_score, issues, pii_detections, flagged, frames_analyzed
    """
    if not video_file_or_path:
        return {
            "flagged": False,
            "risk_score": 0,
            "issues": [],
            "pii_detections": [],
            "frames_analyzed": 0,
        }

    frames = _extract_video_frames(video_file_or_path, max_frames=max_frames)
    if not frames:
        # Video decoding was not possible or file had 0 frames
        return {
            "flagged": False,
            "risk_score": 0,
            "issues": [],
            "pii_detections": [],
            "frames_analyzed": 0,
        }

    issues = []
    pii_detections = []
    max_video_score = 0
    flagged = False

    def check_single_frame(frame_info):
        t_str, pil_img = frame_info
        img_url = _prepare_image_for_moderation(pil_img)
        if not img_url:
            return None
        payload = [{"type": "image_url", "image_url": {"url": img_url}}]
        res = _run_openai_moderation(payload)
        return (t_str, pil_img, res)

    # Check frames concurrently
    with ThreadPoolExecutor(max_workers=min(4, len(frames))) as executor:
        results = list(executor.map(check_single_frame, frames))

    for item in results:
        if not item:
            continue
        t_str, pil_img, openai_res = item
        if not openai_res:
            continue
        f_flagged, f_scores, f_categories = openai_res
        if f_flagged:
            flagged = True

        for cat_key, config in CATEGORY_CONFIG.items():
            score = f_scores.get(cat_key, 0.0)
            is_cat_flagged = f_categories.get(cat_key, False)
            if is_cat_flagged or score >= 0.30:
                cat_score_100 = round(score * 100)
                if is_cat_flagged and cat_score_100 < 70:
                    cat_score_100 = 70
                severity = "CRITICAL" if cat_score_100 >= 90 or config["default_severity"] == "CRITICAL" else (
                    "HIGH" if cat_score_100 >= 70 or config["default_severity"] == "HIGH" else "MEDIUM"
                )
                max_video_score = max(max_video_score, cat_score_100)
                issues.append({
                    "group": config["group"],
                    "risk_type": f"{config['label']} in Video",
                    "category_key": cat_key,
                    "severity": severity,
                    "score": cat_score_100,
                    "risk_weight": cat_score_100,
                    "description": f"{config['description']} (Detected at {t_str})",
                    "masked_value": f"Video Frame at {t_str} ({config['label']} - {cat_score_100}%)",
                    "recommendation": f"Trim or remove the scene at {t_str} before posting.",
                    "source": "video",
                    "timestamp": t_str,
                })

    return {
        "flagged": flagged or bool(issues),
        "risk_score": max_video_score,
        "issues": issues,
        "pii_detections": pii_detections,
        "frames_analyzed": len(frames),
    }


# =====================================================================
# Full Post Moderation Pipeline
# Aggregates Text + Image + Video Analysis
# Computes Risk Score (0-100), Risk Level, and Moderation Status
# =====================================================================

def moderate_post_content(text="", location="", location_full="", feeling="", image=None, video=None):
    """
    Comprehensive multi-modal content moderation before publication.
    - Analyzes every image and video
    - Detects harmful, explicit, violent, sensitive, or inappropriate content
    - Generates Risk Score from 0–100
    - Assigns Risk Level: Low, Medium, High, or Critical
    - Assigns Moderation Status:
        * Allowed (Low risk: 0–29)
        * Flagged for Review (Medium risk: 30–69)
        * Blocked (High / Critical risk: 70–100)
    """
    full_text = " ".join([v.strip() for v in [text, location, location_full, feeling] if v and v.strip()])

    all_detections = []
    category_groups_detected = set()

    # 1. Moderate Text
    text_result = moderate_text(full_text)
    for issue in text_result["issues"]:
        all_detections.append(issue)
        category_groups_detected.add(issue["group"])
    for pii in text_result["pii_detections"]:
        all_detections.append(pii)
        category_groups_detected.add("Sensitive")

    # 2. Moderate Image
    image_result = moderate_image(image) if image else None
    if image_result:
        for issue in image_result["issues"]:
            all_detections.append(issue)
            category_groups_detected.add(issue["group"])
        for pii in image_result["pii_detections"]:
            all_detections.append(pii)
            category_groups_detected.add("Sensitive")

    # 3. Moderate Video
    video_result = moderate_video(video) if video else None
    if video_result:
        for issue in video_result["issues"]:
            all_detections.append(issue)
            category_groups_detected.add(issue["group"])
        for pii in video_result["pii_detections"]:
            all_detections.append(pii)
            category_groups_detected.add("Sensitive")

    # Deduplicate detections
    seen_keys = set()
    unique_detections = []
    for d in all_detections:
        key = (d.get("source"), d.get("risk_type"), d.get("masked_value"), d.get("timestamp"))
        if key not in seen_keys:
            seen_keys.add(key)
            unique_detections.append(d)

    # 4. Calculate Risk Score (0–100)
    if not unique_detections:
        overall_score = 0
    else:
        # AI content category max score
        ai_scores = [d["score"] for d in unique_detections if d.get("group") != "Sensitive"]
        max_ai_score = max(ai_scores) if ai_scores else 0

        # Sensitive PII cumulative score
        pii_weights = [d["risk_weight"] for d in unique_detections if d.get("group") == "Sensitive"]
        total_pii_score = min(sum(pii_weights), 100)

        overall_score = max(max_ai_score, total_pii_score)

        # Critical severity escalation
        if any(d.get("severity") == "CRITICAL" for d in unique_detections):
            overall_score = max(overall_score, 90)
        elif any(d.get("severity") == "HIGH" for d in unique_detections):
            overall_score = max(overall_score, 70)
        elif any(d.get("severity") == "MEDIUM" for d in unique_detections):
            overall_score = max(overall_score, 35)

    overall_score = min(max(int(overall_score), 0), 100)

    # 5. Determine Risk Level: Low, Medium, High, Critical
    if overall_score <= 29:
        risk_level = "Low"
    elif overall_score <= 69:
        risk_level = "Medium"
    elif overall_score <= 89:
        risk_level = "High"
    else:
        risk_level = "Critical"

    # 6. Automated Moderation Decision:
    # Low -> Allowed
    # Medium -> Flagged for Review
    # High / Critical -> Blocked
    if risk_level == "Low":
        moderation_status = "Allowed"
        status_message = "Content passed AI safety moderation and is approved for publication."
    elif risk_level == "Medium":
        moderation_status = "Flagged for Review"
        status_message = "Content contains sensitive or borderline elements and is flagged for review."
    else:
        moderation_status = "Blocked"
        status_message = "Content violates safety policies and is automatically blocked."

    # Misuse mapping
    risk_types = [d["risk_type"] for d in unique_detections]
    misuse_list = possible_misuse_for(risk_types)

    return {
        "risk_score": overall_score,
        "risk_level": risk_level,
        "moderation_status": moderation_status,
        "status_message": status_message,
        "detections": unique_detections,
        "category_groups": sorted(list(category_groups_detected)),
        "possible_misuse": misuse_list,
        "can_publish": moderation_status == "Allowed",
        "is_review": moderation_status == "Flagged for Review",
        "is_blocked": moderation_status == "Blocked",
        "frames_analyzed": video_result["frames_analyzed"] if video_result else 0,
    }


# =====================================================================
# Backend Anti-Bypass Guard
# Enforces server-side authority to prevent any bypass
# =====================================================================

def verify_publication_guard(scan_result):
    """
    Authoritative backend check.
    Returns (permitted: bool, reason: str).
    """
    if not scan_result:
        return False, "Moderation check was not completed."

    status = scan_result.get("moderation_status", "Blocked")
    score = scan_result.get("risk_score", 100)
    level = str(scan_result.get("risk_level", "High")).upper()

    if status == "Blocked" or level in ("HIGH", "CRITICAL"):
        return False, f"Publication Blocked: Content exceeds safety thresholds (Risk Level: {level}, Score: {score}/100)."

    if status == "Flagged for Review" or level in ("MEDIUM", "MODERATE"):
        return True, "Content permitted under review status."

    if status == "Allowed" or level in ("LOW", "SAFE"):
        return True, "Content approved for publication."

    return False, "Invalid moderation status."
