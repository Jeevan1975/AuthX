from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.conf import settings
import uuid

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
    
    
    

class VerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="verification_tokens")
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
        return f"VerificationToken(user={self.user.username}, used={self.used})"
    
    
    

class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="refresh_tokens")
    jti = models.CharField(max_length=255, unique=True, db_index=True)
    token_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    last_used_at = models.DateTimeField(null=True, blank=True)
    device_info = models.JSONField(null=True, blank=True)
    rotation_count = models.IntegerField(default=0)

    def is_expired(self):
        return timezone.now() > self.expires_at 
    
    def mark_revoked(self):
        self.revoked = True
        self.save(update_fields=["revoked"])
    
    def __str__(self):
        return f"RefreshToken(user={self.user_id}, jti={self.jti}, revoke={self.revoked})"