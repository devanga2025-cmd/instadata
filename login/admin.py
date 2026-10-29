from django.contrib import admin

from .models import UserLoginHistory


@admin.register(UserLoginHistory)
class UserLoginHistoryAdmin(admin.ModelAdmin):
    list_display = ("user", "login_time", "ip_address")
    search_fields = ("user__username", "user__email", "ip_address")
    list_filter = ("login_time",)
