from unittest.mock import patch

from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from account.models import UserRegistration
from home.models import Post
from privacy_engine.services.image_detector import _detect_ocr_privacy
from privacy_engine.services.risk_calculator import calculate_score, level_for_score


@override_settings(MEDIA_ROOT='D:/Major_project/test_media')
class CreatePostTests(TestCase):
    def setUp(self):
        self.user = UserRegistration.objects.create(
            full_name='New User',
            username='newuser',
            email='newuser@example.com',
            password='password123',
            confirm_password='password123',
            agreed_to_terms=True,
        )
        session = self.client.session
        session['user_id'] = self.user.id
        session.save()

    def test_photo_ocr_detects_phone_without_inventing_a_plate(self):
        detections = _detect_ocr_privacy([
            ([[20, 20], [480, 20], [480, 70], [20, 70]], 'Call +91 9876543210', 0.96),
        ])

        self.assertIn('Phone Number', [item['risk_type'] for item in detections])
        self.assertNotIn('Vehicle Registration Number', [item['risk_type'] for item in detections])

    def test_same_ocr_detection_from_multiple_passes_is_merged(self):
        detections = _detect_ocr_privacy([
            ([[20, 20], [480, 20], [480, 70], [20, 70]], 'Call +91 9876543210', 0.96),
            ([[21, 21], [481, 21], [481, 71], [21, 71]], 'Call +91 9876543210', 0.91),
        ])

        self.assertEqual(sum(item['risk_type'] == 'Phone Number' for item in detections), 1)

    def test_nonzero_privacy_risk_is_never_labeled_safe(self):
        self.assertEqual(level_for_score(0), 'SAFE')
        self.assertEqual(level_for_score(20), 'LOW')
        _, level = calculate_score([{'risk_type': 'Phone Number', 'risk_weight': 20}])
        self.assertEqual(level, 'LOW')

    @patch('createpost.views._store_scan')
    @patch('createpost.views._scan_post_content')
    def test_video_only_post_can_be_published(self, scan_post_content, store_scan):
        scan_post_content.return_value = {
            'risk_score': 0,
            'risk_level': 'SAFE',
            'detections': [],
            'possible_misuse': [],
        }
        video = SimpleUploadedFile('moment.mp4', b'video-content', content_type='video/mp4')

        response = self.client.post(reverse('create_post'), {
            'action': 'publish',
            'content': '',
            'media': video,
        })

        self.assertRedirects(response, reverse('home'))
        post = Post.objects.get(author=self.user)
        self.assertTrue(post.video.name.startswith('pending_post_videos/moment'))
        self.assertTrue(post.video.name.endswith('.mp4'))
        self.assertEqual(post.content, '')
        store_scan.assert_called_once()

    @patch('createpost.views.protect_image_privacy')
    @patch('createpost.views._scan_post_content')
    def test_protect_image_rechecks_the_protected_file(self, scan_post_content, protect_image):
        scan_post_content.return_value = {
            'risk_score': 0,
            'risk_level': 'SAFE',
            'detections': [],
            'possible_misuse': [],
        }
        protect_image.return_value = ContentFile(b'protected-image')
        image = SimpleUploadedFile('receipt.jpg', b'original-image', content_type='image/jpeg')

        response = self.client.post(reverse('create_post'), {
            'action': 'protect_image',
            'content': '',
            'media': image,
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Privacy Scan Complete')
        protect_image.assert_called_once()
        self.assertEqual(scan_post_content.call_count, 1)

    @patch('createpost.views._scan_post_content')
    def test_medium_risk_image_cannot_be_published(self, scan_post_content):
        scan_post_content.return_value = {
            'risk_score': 45,
            'risk_level': 'MEDIUM',
            'detections': [{
                'risk_type': 'Vehicle Registration Number',
                'masked_value': 'plate-like region',
                'severity': 'HIGH',
                'risk_weight': 45,
                'recommendation': 'Protect the image before posting.',
                'source': 'image',
            }],
            'possible_misuse': [],
        }
        image = SimpleUploadedFile('car.jpg', b'car-image', content_type='image/jpeg')

        response = self.client.post(reverse('create_post'), {
            'action': 'publish',
            'content': '',
            'media': image,
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Posting Blocked')
        self.assertFalse(Post.objects.filter(author=self.user).exists())

    def test_ai_moderation_evaluates_safe_content_as_allowed(self):
        from createpost.ai_moderation import moderate_post_content
        result = moderate_post_content(text="Wonderful afternoon walking through the botanical gardens.")
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["moderation_status"], "Allowed")
        self.assertTrue(result["can_publish"])
        self.assertLessEqual(result["risk_score"], 29)

    def test_ai_moderation_blocks_violent_harmful_content(self):
        from createpost.ai_moderation import moderate_post_content
        result = moderate_post_content(text="I will kill you and cut your throat with a knife")
        self.assertIn(result["risk_level"], ["High", "Critical"])
        self.assertEqual(result["moderation_status"], "Blocked")
        self.assertFalse(result["can_publish"])
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertTrue(any(d.get("group") in ("Violent", "Harmful") for d in result["detections"]))

    def test_backend_publish_guard_strictly_blocks_bypass(self):
        from createpost.ai_moderation import verify_publication_guard
        blocked_scan = {
            "risk_score": 90,
            "risk_level": "Critical",
            "moderation_status": "Blocked",
            "detections": [{"risk_type": "Violent Threat", "severity": "CRITICAL"}],
        }
        permitted, reason = verify_publication_guard(blocked_scan)
        self.assertFalse(permitted)
        self.assertIn("Publication Blocked", reason)

        # Attempt to publish blocked content directly via POST
        with patch('createpost.views._scan_post_content') as mock_scan:
            mock_scan.return_value = blocked_scan
            response = self.client.post(reverse('create_post'), {
                'action': 'publish',
                'content': 'Violent threat that tries to bypass moderation',
            })
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "Publication Blocked")
            self.assertFalse(Post.objects.filter(content='Violent threat that tries to bypass moderation').exists())

    def test_video_analysis_extracts_and_scans_frames(self):
        import cv2, tempfile, os, numpy as np
        from createpost.ai_moderation import moderate_video

        # Create dummy 10-frame video
        temp_vid = os.path.join(tempfile.gettempdir(), 'test_sample_mod.mp4')
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(temp_vid, fourcc, 10.0, (80, 80))
        for i in range(10):
            frame = np.full((80, 80, 3), 100, dtype=np.uint8)
            out.write(frame)
        out.release()

        try:
            res = moderate_video(temp_vid, max_frames=3)
            self.assertGreaterEqual(res["frames_analyzed"], 1)
            self.assertIn("risk_score", res)
        finally:
            if os.path.exists(temp_vid):
                os.remove(temp_vid)

    def test_end_to_end_safe_post_created_with_moderation_fields(self):
        response = self.client.post(reverse('create_post'), {
            'action': 'publish',
            'content': 'Enjoying a quiet morning reading books at the library!',
        })
        self.assertRedirects(response, reverse('home'))
        post = Post.objects.get(author=self.user)
        self.assertEqual(post.moderation_status, 'Allowed')
        self.assertEqual(post.risk_level, 'Low')
        self.assertEqual(post.risk_score, 0)
        self.assertIn('Verified Safe', post.detected_issues)

    def test_medium_risk_content_submitted_for_review(self):
        medium_scan = {
            "risk_score": 40,
            "risk_level": "Medium",
            "moderation_status": "Flagged for Review",
            "detections": [{
                "risk_type": "Vehicle Registration Number",
                "severity": "MEDIUM",
                "risk_weight": 25,
                "masked_value": "[PLATE]",
                "recommendation": "Protect the plate.",
                "source": "image",
                "group": "Sensitive",
            }],
            "possible_misuse": [],
            "can_publish": False,
            "is_review": True,
            "is_blocked": False,
        }
        with patch('createpost.views._scan_post_content') as mock_scan:
            mock_scan.return_value = medium_scan
            response = self.client.post(reverse('create_post'), {
                'action': 'publish_under_review',
                'content': 'Checking out this car',
            })
            self.assertRedirects(response, reverse('home'))
            post = Post.objects.get(content='Checking out this car')
            self.assertEqual(post.moderation_status, 'Flagged for Review')
            self.assertEqual(post.risk_level, 'Medium')


