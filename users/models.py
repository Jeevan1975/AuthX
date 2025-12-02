from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta

class User(AbstractUser):
    pass




class ResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reset_tokens")
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def mark_used(self):
        self.used = True
        self.save()
    
    def __str__(self):
        return f"ResetToken(user={self.user.username}, used={self.used})"