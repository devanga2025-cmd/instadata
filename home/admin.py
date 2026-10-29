

# Register your models here.
from django.contrib import admin
from .models import DetectedRisk, Post, PrivacyScan, PrivacyTip

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'content_preview', 'likes', 'comments', 'created_at')
    list_filter = ('privacy', 'created_at')
    search_fields = ('author__username', 'content')
    
    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = 'Content Preview'

@admin.register(PrivacyTip)
class PrivacyTipAdmin(admin.ModelAdmin):
    list_display = ('title', 'description', 'created_at')


class DetectedRiskInline(admin.TabularInline):
    model = DetectedRisk
    extra = 0
    readonly_fields = ('risk_type', 'masked_value', 'severity', 'risk_weight', 'recommendation')
    can_delete = False


@admin.register(PrivacyScan)
class PrivacyScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'post', 'risk_score', 'risk_level', 'created_at')
    list_filter = ('risk_level', 'created_at')
    search_fields = ('user__username', 'detected_risks__risk_type')
    inlines = (DetectedRiskInline,)
