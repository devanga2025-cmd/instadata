from django.db import models
from account.models import UserRegistration

# Create your models here.


# NEW MODEL: Handles the Login Page (Foreign Key to the Account)
class UserLoginHistory(models.Model):
    user = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='login_history')
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} logged in at {self.login_time}"
