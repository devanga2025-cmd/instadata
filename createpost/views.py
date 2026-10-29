from django.shortcuts import render, redirect
from account.models import UserRegistration
from home.models import DetectedRisk, Post, PrivacyScan
from django.contrib import messages
from django.core.files.storage import default_storage
from privacy_engine.services.image_detector import protect_image_privacy
from privacy_engine.services.text_detector import remove_sensitive_text
from .ai_moderation import moderate_post_content, verify_publication_guard


IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"}
VIDEO_CONTENT_TYPES = {"video/mp4", "video/webm", "video/quicktime", "video/x-msvideo", "video/x-matroska"}


def _is_image_file(uploaded_file):
    return bool(uploaded_file and getattr(uploaded_file, "content_type", "") in IMAGE_CONTENT_TYPES)


def _is_video_file(uploaded_file):
    return bool(uploaded_file and getattr(uploaded_file, "content_type", "") in VIDEO_CONTENT_TYPES)


def _scan_fields(content, *fields):
    """Include optional public post fields in the scan."""
    extra = " ".join(value.strip() for value in fields if value and value.strip())
    return f"{content} {extra}".strip()


def _scan_post_content(content, image=None, video=None):
    """
    Analyzes post content, image, and video using multimodal AI moderation and privacy detection.
    """
    result = moderate_post_content(
        text=content,
        image=image,
        video=video,
    )
    return result


def _store_scan(user, post, scan_result):
    """Save moderation scan and detected risks in database."""
    privacy_scan = PrivacyScan.objects.create(
        user=user,
        post=post,
        risk_score=scan_result.get("risk_score", 0),
        risk_level=scan_result.get("risk_level", "Low"),
        moderation_status=scan_result.get("moderation_status", "Allowed"),
    )
    DetectedRisk.objects.bulk_create([
        DetectedRisk(
            privacy_scan=privacy_scan,
            risk_type=item["risk_type"],
            masked_value=item.get("masked_value", "[REDACTED]"),
            severity=item.get("severity", "MEDIUM"),
            risk_weight=item.get("risk_weight", 0),
            recommendation=item.get("recommendation", "Review content before posting."),
            category=item.get("group", item.get("category", "sensitive")),
            source=item.get("source", "text"),
        )
        for item in scan_result.get("detections", [])
    ])
    return privacy_scan


def _get_context(user, content="", scan_result=None, safe_message=False, pending_image_path="", pending_video_path=""):
    has_image_risks = bool(scan_result and any(
        item.get("source") == "image" and item.get("risk_type") != "Image analysis unavailable"
        for item in scan_result.get("detections", [])
    ))
    
    # Check if publish is allowed
    # Allowed only if Low risk / no blocking detections
    moderation_status = "Allowed"
    if scan_result:
        moderation_status = scan_result.get("moderation_status", "Allowed")
        risk_level = str(scan_result.get("risk_level", "Low")).upper()
        if not scan_result.get("detections") and risk_level in ("SAFE", "LOW"):
            moderation_status = "Allowed"
            can_publish = True
        elif moderation_status == "Allowed" and not scan_result.get("is_blocked"):
            can_publish = True
        else:
            can_publish = False
    else:
        can_publish = False

    return {
        "user": user,
        "content": content,
        "scan_result": scan_result,
        "safe_message": safe_message,
        "can_publish": can_publish,
        "pending_image_path": pending_image_path,
        "pending_video_path": pending_video_path,
        "has_protectable_image": bool(pending_image_path and has_image_risks),
        "has_image_risks": has_image_risks,
    }


def _save_pending_image(image):
    if not image:
        return ""
    return default_storage.save(f"pending_post_images/{image.name}", image)


def _save_pending_video(video):
    if not video:
        return ""
    return default_storage.save(f"pending_post_videos/{video.name}", video)


def _open_pending_image(path):
    if not path:
        return None
    try:
        return default_storage.open(path, "rb")
    except FileNotFoundError:
        return None


def _open_pending_video(path):
    if not path:
        return None
    try:
        return default_storage.open(path, "rb")
    except FileNotFoundError:
        return None


def create_post_view(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        current_user = UserRegistration.objects.get(id=user_id)
    except UserRegistration.DoesNotExist:
        request.session.flush()
        return redirect('login')

    if request.method == 'POST':
        action = request.POST.get('action', 'analyze')
        content = request.POST.get('content', '').strip()
        location = request.POST.get('location', '').strip()
        location_full = request.POST.get('location_full', '').strip()
        feeling = request.POST.get('feeling', '').strip()
        media = request.FILES.get('media') or request.FILES.get('image')
        pending_image_path = request.POST.get('pending_image_path', '')
        pending_video_path = request.POST.get('pending_video_path', '')

        if media:
            if _is_image_file(media):
                pending_image_path = _save_pending_image(media)
                pending_video_path = ""
            elif _is_video_file(media):
                pending_video_path = _save_pending_video(media)
                pending_image_path = ""
            else:
                messages.error(request, "Please upload a supported image or video file.")
                return render(request, 'create_post/post.html', _get_context(current_user, content))

        scan_image = _open_pending_image(pending_image_path)
        scan_video = pending_video_path or None

        if not content and not location and not location_full and not feeling and not pending_image_path and not pending_video_path:
            messages.error(request, "Add text, an image, or a video before posting.")
            return render(request, 'create_post/post.html', _get_context(current_user, content))

        # Handle user remediation actions
        if action == "remove_sensitive":
            cleaned_content = remove_sensitive_text(content)
            scan_result = _scan_post_content(_scan_fields(cleaned_content, location, location_full, feeling), scan_image, scan_video)
            is_safe = (scan_result.get("moderation_status") == "Allowed" or scan_result.get("risk_level") in ("SAFE", "Low", "LOW"))
            return render(
                request,
                'create_post/post.html',
                _get_context(current_user, cleaned_content, scan_result, is_safe, pending_image_path, pending_video_path),
            )

        if action == "protect_image":
            if not scan_image:
                messages.error(request, "Please choose an image before protecting it.")
                return render(request, 'create_post/post.html', _get_context(current_user, content, pending_image_path=pending_image_path, pending_video_path=pending_video_path))

            protected_image = protect_image_privacy(scan_image)
            if not protected_image:
                messages.error(request, "The image could not be protected automatically. Please choose another image or edit it manually.")
                scan_result = _scan_post_content(_scan_fields(content, location, location_full, feeling), scan_image, scan_video)
                return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, pending_image_path=pending_image_path, pending_video_path=pending_video_path))

            pending_image_path = default_storage.save("pending_post_images/protected_image.jpg", protected_image)
            scan_image = _open_pending_image(pending_image_path)
            scan_result = _scan_post_content(_scan_fields(content, location, location_full, feeling), scan_image, scan_video)
            is_safe = (scan_result.get("moderation_status") == "Allowed" or scan_result.get("risk_level") in ("SAFE", "Low", "LOW"))
            messages.success(request, "Sensitive image regions were protected and metadata was removed. Image re-analyzed.")
            return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, is_safe, pending_image_path, pending_video_path))

        # Run backend multi-modal AI moderation
        content_to_scan = _scan_fields(content, location, location_full, feeling)
        scan_result = _scan_post_content(content_to_scan, scan_image, scan_video)

        # Normalize status if missing from mocked test responses
        if "moderation_status" not in scan_result:
            r_level = str(scan_result.get("risk_level", "Low")).upper()
            if r_level in ("SAFE", "LOW") and not scan_result.get("detections"):
                scan_result["moderation_status"] = "Allowed"
            elif r_level in ("HIGH", "CRITICAL"):
                scan_result["moderation_status"] = "Blocked"
            else:
                scan_result["moderation_status"] = "Flagged for Review"

        # AUTHORITATIVE BACKEND ENFORCEMENT ON PUBLISH
        if action == "publish":
            # Guard against bypass: Verify moderation results on backend
            is_permitted, reason = verify_publication_guard(scan_result)
            
            # If any detections exist or content is not strictly Allowed, block publication
            if scan_result.get("detections") or not is_permitted or scan_result.get("moderation_status") != "Allowed":
                if scan_result.get("moderation_status") == "Blocked":
                    messages.error(request, f"Publication Blocked: Content violates safety policies (Risk Score: {scan_result.get('risk_score')}/100, Level: {scan_result.get('risk_level')}).")
                else:
                    messages.error(request, "Sensitive information or policy violation detected. Remove it or choose safer media before posting.")
                return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, pending_image_path=pending_image_path, pending_video_path=pending_video_path))

            # Content is verified and Allowed -> Create Post
            post = Post.objects.create(
                author=current_user,
                content=content,
                image=pending_image_path or None,
                video=pending_video_path or None,
                moderation_status="Allowed",
                risk_score=scan_result.get("risk_score", 0),
                risk_level=scan_result.get("risk_level", "Low"),
                detected_issues="None - Verified Safe",
            )
            _store_scan(current_user, post, scan_result)
            messages.success(request, "Post published successfully!")
            return redirect('home')

        if action == "publish_under_review":
            # User submits medium-risk content flagged for moderation review
            if scan_result.get("moderation_status") == "Blocked" or scan_result.get("risk_level") in ("High", "Critical", "HIGH", "CRITICAL"):
                messages.error(request, "This post cannot be submitted because it violates high-risk safety policies.")
                return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, pending_image_path=pending_image_path, pending_video_path=pending_video_path))

            post = Post.objects.create(
                author=current_user,
                content=content,
                image=pending_image_path or None,
                video=pending_video_path or None,
                moderation_status="Flagged for Review",
                risk_score=scan_result.get("risk_score", 40),
                risk_level=scan_result.get("risk_level", "Medium"),
                detected_issues=str([d.get("risk_type") for d in scan_result.get("detections", [])]),
            )
            _store_scan(current_user, post, scan_result)
            messages.warning(request, "Your post has been submitted and is currently flagged for review.")
            return redirect('home')

        # Analysis view (before posting display)
        if scan_result.get("moderation_status") == "Allowed" or scan_result.get("risk_level") in ("SAFE", "Low", "LOW"):
            messages.success(request, "Content safety check passed. Your post is safe to share.")
            return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, True, pending_image_path, pending_video_path))

        if scan_result.get("moderation_status") == "Flagged for Review":
            messages.warning(request, "Content flagged for review. Please check the detected items.")
            return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, pending_image_path=pending_image_path, pending_video_path=pending_video_path))

        messages.error(request, "Content safety risk detected. This content cannot be published as is.")
        return render(request, 'create_post/post.html', _get_context(current_user, content, scan_result, pending_image_path=pending_image_path, pending_video_path=pending_video_path))

    return render(request, 'create_post/post.html', _get_context(current_user))
