# AI-Powered Content Moderation & User Data Privacy Guide

> **Project:** U Day Social Platform  
> **Core Architecture:** Multimodal AI Content Moderation & Multi-Tier Privacy Protection Engine  
> **Backend:** Django (Python), OpenCV, OpenAI Moderation API, EasyOCR  

---

## 1. Executive Summary

This project implements an intelligent, server-enforced **AI Content Moderation and Privacy Protection System**. Before any post, image, or video is published to the public feed, it undergoes automated scanning on the backend to detect:
1. **Harmful Content:** Hate speech, targeted harassment, cyberbullying, threats, and self-harm.
2. **Explicit Content:** Sexual material, NSFW media, and prohibited adult content.
3. **Violent Content:** Physical violence, weapons, gore, blood, and criminal acts.
4. **Sensitive Personal Data (PII):** Phone numbers, email addresses, government IDs (Aadhaar, PAN, SSN, Passport), bank accounts, credit cards, passwords, OTPs, home addresses, license plates, and GPS location metadata.
5. **Inappropriate Content:** Illicit activities, controlled contraband, and abusive profanity.

The system evaluates all content, calculates a **Risk Score from 0 to 100**, categorizes it into a **Risk Level (Low, Medium, High, or Critical)**, and triggers automated moderation decisions:
* **Low Risk (0–29):** **Allowed** — content is safe and published immediately.
* **Medium Risk (30–69):** **Flagged for Review** — content has potential risks; user is alerted to edit or submit for human review.
* **High & Critical Risk (70–100):** **Blocked** — automatically blocked from publication on the server.

All checks are strictly validated on the **backend**, meaning malicious users cannot bypass moderation using modified browser tools, scripts, or direct API requests.

---

## 2. How the Project Works (Step-by-Step Architecture)

```
[ User Input ]
   ├── Caption & Text Fields (Content, Location, Activity)
   ├── Photo Upload (JPEG, PNG, WEBP)
   └── Video Upload (MP4, WebM, MOV)
           │
           ▼
[ Backend AI Moderation Engine ]
   ├── Text Moderation: OpenAI omni-moderation + Regex Heuristics
   ├── Image Moderation: Multimodal AI Vision + EasyOCR + EXIF Inspector
   └── Video Moderation: OpenCV Frame Sampling + Frame-by-Frame AI Analysis
           │
           ▼
[ Threat & Privacy Classification ]
   Categorizes issues into: Harmful, Explicit, Violent, Sensitive, Inappropriate
           │
           ▼
[ Scoring & Decision Engine ]
   ├── Computes Risk Score (0–100)
   ├── Assigns Risk Level: Low (0-29) | Medium (30-69) | High (70-89) | Critical (90-100)
   └── Moderation Decision: Allowed | Flagged for Review | Blocked
           │
           ▼
[ Pre-Posting Feedback to User ]
   Modal displays: Status Badge, Risk Score Meter, Issue Breakdown, Recommendations
           │
           ▼
[ Server-Side Publish Gatekeeper ]
   ├── If Blocked (High/Critical)  ──> Refuses DB save, keeps post blocked
   ├── If Flagged for Review (Med) ──> Saves with 'Flagged for Review' status
   └── If Allowed (Low Risk)       ──> Publishes to feed with 'Verified Safe' badge
```

---

### Step 1: Content Intake
When a user prepares a post, they can provide:
* Text caption, location tags, and activity/feeling descriptions.
* An image (photo) or video clip.
The user clicks **"Analyze & Post"**.

### Step 2: Multimodal Backend Analysis
The platform never publishes content directly upon upload. Everything is analyzed on the backend:
1. **Text Analysis (`moderate_text`):**
   * Combines all textual inputs into an aggregated text payload.
   * Dispatches the text to the AI moderation service (`omni-moderation-latest`) to detect hate speech, harassment, self-harm, threats, and illicit terms.
   * Runs the PII Privacy Detector to locate phone numbers, emails, passwords, OTPs, and identification numbers.
2. **Image Analysis (`moderate_image`):**
   * Strips orientation metadata, standardizes dimensions, and encodes the image into base64.
   * Submits the visual data to the AI moderation vision model to detect explicit nudity, weapons, graphic violence, or hate symbols.
   * Runs EasyOCR to detect text printed in the image (such as identity cards, credit cards, or receipts) and checks EXIF data for GPS coordinates.
3. **Video Analysis (`moderate_video`):**
   * Decodes the video using **OpenCV (`cv2.VideoCapture`)**.
   * Identifies total frames and FPS, then samples representative keyframes across the timeline (e.g., at 10%, 30%, 50%, 70%, 90% of the video).
   * Concurrently processes keyframes through the AI visual model and OCR detector.
   * Records the exact timestamp (e.g., `00:03`) for any frame containing violence, weapons, explicit scenes, or sensitive details.

### Step 3: Risk Score (0–100) and Level Calculation
The system merges findings from all media:
$$\text{Risk Score} = \min\left(100, \max(\text{Max AI Category Score} \times 100, \sum \text{Sensitive Weights})\right)$$

* Any **Critical violation** (child exploitation, graphic violence, self-harm instructions, leaked bank credentials) automatically elevates the score to **90–100**.
* **Risk Levels:**
  * **Low (0–29):** Safe for all users.
  * **Medium (30–69):** Contains mild or borderline sensitive elements (e.g., license plate visible, contact details).
  * **High (70–89):** High-risk violation (harassment, violence, adult content).
  * **Critical (90–100):** Severe danger or critical policy breach.

### Step 4: Automated Moderation Actions
* **Allowed:** Content is cleared for immediate publication.
* **Flagged for Review:** Content is flagged. The user is prompted to clean the post or submit it for review.
* **Blocked:** Publishing is disabled. The user cannot post until the violations are removed.

### Step 5: Backend Anti-Bypass Guard
Even if a user tries to circumvent the browser interface (e.g., disabling JavaScript, crafting a custom HTTP POST request with `action=publish`), the server's `verify_publication_guard()` re-evaluates the scan results on the server:
* If the post is `Blocked` or risk level is `High` / `Critical`, the server **rejects the request**, refuses to write to the `Post` database table, and returns a 403/warning response.

---

## 3. How the Project Protects and Safes User Personal Data

Privacy protection is built into the core architecture of the system:

### 1. Zero-Leakage PII Masking
* When the scanner identifies sensitive information (such as an Aadhaar number, phone number, or email), the raw data is **never shown in full on the screen** or logged in cleartext.
* Masked placeholders are displayed instead (e.g., `+91 98******10`, `a****@example.com`, `[AADHAAR DETECTED]`), preventing shoulder surfing or accidental screen leakage.

### 2. Automatic GPS Metadata (EXIF) Stripping
* Smartphone photos and videos often embed exact GPS coordinates in EXIF tags, revealing a user's exact home or work location.
* The system inspects and strips all GPS and device metadata prior to storage and public rendering.

### 3. Visual Sensitive Data Masking ("Protect Image")
* If an image contains private text (such as a vehicle number plate, identity card, or travel boarding pass), the user can click **"Protect Image"**.
* The system automatically blurs or black-boxes the sensitive coordinate regions using OpenCV and removes all metadata, allowing the user to share the photo safely.

### 4. Ephemeral Pending Media Storage
* Files uploaded for analysis are held in a secure staging directory (`pending_post_images/` and `pending_post_videos/`).
* If a post is blocked or discarded, temporary media is cleared and never exposed on the public timeline.

### 5. Secure Credential Protection
* User passwords are encrypted using secure cryptographic hashing (PBKDF2 with SHA-256) with unique per-user salts. Plaintext passwords are never stored.

### 6. Fail-Closed Server Gatekeeping
* The moderation system follows a **Fail-Closed** security principle:
  * If media cannot be analyzed or if analysis indicates high risk, publication remains blocked by default.
  * Client-side JavaScript cannot force a publish event because the server independently validates the content before saving.

---

## 4. Moderation Levels & Actions Summary

| Risk Score | Risk Level | Moderation Status | Automated Action | Typical Causes |
| :---: | :---: | :---: | :---: | :--- |
| **0 – 29** | **Low** | **Allowed** | Published immediately | Clean captions, scenic photos, family-friendly videos |
| **30 – 69** | **Medium** | **Flagged for Review** | Flagged for manual review / User warned | Visible phone number, vehicle plate, borderline sensitive topic |
| **70 – 89** | **High** | **Blocked** | Automatically blocked from publication | Direct harassment, violent threats, weapons, explicit adult imagery |
| **90 – 100** | **Critical** | **Blocked** | Automatically blocked immediately | Graphic gore, self-harm instructions, bank credentials, severe explicit acts |

---

## 5. Verification & Testing

The system includes automated tests validating every component:
* `test_ai_moderation_evaluates_safe_content_as_allowed`: Verifies safe posts receive score < 30 and `Allowed` status.
* `test_ai_moderation_blocks_violent_harmful_content`: Verifies violent/harmful posts receive score >= 70 and `Blocked` status.
* `test_backend_publish_guard_strictly_blocks_bypass`: Verifies direct POST publish attempts with blocked content are rejected on the server.
* `test_video_analysis_extracts_and_scans_frames`: Verifies OpenCV extracts and checks multiple video frames across the timeline.
* `test_protect_image_rechecks_the_protected_file`: Verifies sensitive image regions are blurred and re-analyzed.
* `test_end_to_end_safe_post_created_with_moderation_fields`: Verifies approved posts are saved in the database with `moderation_status='Allowed'`, `risk_score=0`, and `risk_level='Low'`.

All 17 automated tests run cleanly and confirm that the system functions securely.

