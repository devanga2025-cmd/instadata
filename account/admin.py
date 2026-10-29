from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import UserRegistration

@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ('username', 'full_name', 'email', 'date_of_birth', 'created_at')
    search_fields = ('username', 'email', 'full_name')
    list_filter = ('created_at',)