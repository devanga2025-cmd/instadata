

# Create your models here.
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User # If using standard auth

# 1. User Registration (Assumed to exist from earlier steps)
class UserRegistration(models.Model):
    full_name = models.CharField(max_length=100)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    privacy_score = models.IntegerField(default=80) # Stored here to persist across sessions
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username

# 2. Updated Post Model (Dynamic fields)
class Post(models.Model):
    author = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(max_length=500)
    image = models.ImageField(upload_to='post_images/', null=True, blank=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    feeling = models.CharField(max_length=50, blank=True, null=True) # e.g., Happy, Excited
    created_at = models.DateTimeField(default=timezone.now)
    privacy = models.CharField(max_length=20, default='Public')
    
    # AI Analysis Results
    is_safe = models.BooleanField(default=True) # True if AI says it's safe
    detected_risk = models.TextField(blank=True, null=True) # What risky data was found

    def __str__(self):
        return f"{self.author.username} - {self.created_at.strftime('%Y-%m-%d')}"