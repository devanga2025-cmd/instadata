# Personal information protection before sharing

## What changed

- The server scans post text and the optional location, full-location, and feeling fields together. A personal detail typed into one of those fields cannot bypass the caption scan.
- Publishing is blocked whenever the scan reports a privacy detection, including low-severity findings. The user must remove the detail and recheck the post before the Publish button becomes available.
- Text findings include patterns for phone numbers, email addresses, common identity numbers, IP addresses, dates of birth, passwords and OTPs, bank details, vehicle registrations, tickets, addresses, travel plans, current locations, and unattended homes. Person and place names are additionally checked when the optional spaCy model is installed.
- Images are checked with OCR for text, QR codes, selected identity/card/ticket clues, and GPS EXIF metadata. If image analysis cannot run, it produces a review finding and publication stays blocked. The existing Protect Image action masks detected regions and removes metadata, then rechecks the result.
- Videos/Reels are accepted as uploads by the form, but this project does not decode or scan video frames. They are now explicitly marked as unanalyzed and blocked from publication instead of being treated as safe. Users can share after video frame scanning is implemented, or use an image/text post for now.
- The create-post form supports the same scan/review flow for both photos and videos; the server-side publish check is authoritative even if a browser bypasses the UI.

## What users do

1. Enter a caption and any optional details, then choose **Analyze & Post**.
2. Review masked detection labels and recommendations. The interface does not display the full detected value.
3. Edit the text or use **Remove Sensitive Data**; for a supported image, use **Protect Image** or choose another image.
4. Recheck. Publish is enabled only when there are no detections.

## Limits

These checks reduce accidental disclosure but cannot guarantee that all personal details are detected. They can miss unusual formats, non-English text, low-quality or obscured image text, and details not covered by the rules. Image OCR setup must work for images to be cleared; unavailable analysis fails closed. Video/Reel scanning is not implemented and video uploads remain blocked. Face recognition and identification are not performed.

## Implementation locations

- `createpost/views.py`: combines public text fields, enforces the server-side gate, and labels unsupported video analysis as a blocking finding.
- `privacy_engine/services/text_detector.py`: text detection rules and sensitive-text removal.
- `privacy_engine/services/image_detector.py`: image OCR, QR/metadata findings, and image protection.
- `templates/create_post/post.html` and `templates/create_post/post.js`: scan results and actions presented to the user.
