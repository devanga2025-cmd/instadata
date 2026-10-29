# Create your models here.
from django.db import models
from django.utils import timezone
from account.models import UserRegistration

# 1. Post Model (For the Dashboard Feed)
class Post(models.Model):
    # Foreign Key linking to existing UserRegistration model
    author = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(max_length=500)
    image = models.ImageField(upload_to='post_images/', null=True, blank=True)
    video = models.FileField(upload_to='post_videos/', null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    privacy = models.CharField(max_length=20, default='Public') # e.g., Public, Friends
    
    # Engagement metrics
    likes = models.IntegerField(default=124)
    comments = models.IntegerField(default=18)
    shares = models.IntegerField(default=5)
    
    # Reactions breakdown
    likes_count = models.IntegerField(default=100)
    loves_count = models.IntegerField(default=20)
    care_count = models.IntegerField(default=4)

    # Content Moderation & Safety Fields
    moderation_status = models.CharField(max_length=30, default='Allowed') # Allowed, Flagged for Review, Blocked
    risk_score = models.IntegerField(default=0) # 0-100
    risk_level = models.CharField(max_length=20, default='Low') # Low, Medium, High, Critical
    detected_issues = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.author.username} - {self.created_at.strftime('%Y-%m-%d')} ({self.moderation_status})"


# 2. Privacy Tip Model (For the Right Sidebar)
class PrivacyTip(models.Model):
    title = models.CharField(max_length=100, default="Privacy Tip of the Day")
    description = models.TextField()
    icon_class = models.CharField(max_length=50, default='fa-lightbulb') # FontAwesome class
    learn_more_link = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class PrivacyScan(models.Model):
    user = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='privacy_scans')
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='privacy_scans', null=True, blank=True)
    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20, default='Low')
    moderation_status = models.CharField(max_length=30, default='Allowed')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.risk_level} ({self.risk_score}) [{self.moderation_status}]"


class DetectedRisk(models.Model):
    privacy_scan = models.ForeignKey(PrivacyScan, on_delete=models.CASCADE, related_name='detected_risks')
    risk_type = models.CharField(max_length=100)
    masked_value = models.CharField(max_length=255)
    severity = models.CharField(max_length=20)
    risk_weight = models.IntegerField()
    recommendation = models.TextField()
    category = models.CharField(max_length=50, default='sensitive') # harmful, explicit, violent, sensitive, inappropriate
    source = models.CharField(max_length=50, default='text') # text, image, video

    def __str__(self):
        return f"{self.risk_type} - {self.severity} ({self.source})"
