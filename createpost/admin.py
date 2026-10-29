

# Register your models here.
from django.contrib import admin
from .models import UserRegistration, Post

@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'full_name', 'email', 'privacy_score')
    search_fields = ('username', 'email')

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'content_preview', 'location', 'feeling', 'is_safe', 'created_at')
    list_filter = ('is_safe', 'privacy', 'created_at')
    search_fields = ('author__username', 'content')
    
    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = 'Content Preview'