from rest_framework import serializers
from django.utils import timezone
from .models import User, ResetToken, VerificationToken
from .utils import generate_reset_token
from datetime import timedelta
import re


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password')
        
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.is_active = False
        user.save()
        return user
    
    
    
    
class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
    EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"
    
    def validate(self, attrs):
        identifier = attrs.get("identifier")
        password = attrs.get("password")
        
        user = None
        
        # Checking if identifier looks like an email
        if re.match(self.EMAIL_REGEX, identifier):
            user = User.objects.filter(email__iexact=identifier).first()

        # If no user found by email -> trying using username
        if not user:
            user = User.objects.filter(username__iexact=identifier).first()
        
        # Still no user
        if not user:
            raise serializers.ValidationError("Invalid username or email")
        
        # Validating password
        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password")
        
        attrs["user"] = user
        return attrs
    
    
    

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate(self, attrs):
        email = attrs.get("email")
        user = User.objects.filter(email__iexact=email).first()
        attrs["user"] = user
        return attrs
    
    
    def save(self):
        user = self.validated_data["user"]
        
        if not user:
            return None
        
        token = generate_reset_token()
        
        ResetToken.objects.create(
            user=user,
            token=token,
            expires_at=timezone.now() + timedelta(minutes=15)
        )
        
        return token
    
    
    

class PasswordResetValidateSerializer(serializers.Serializer):
    token = serializers.CharField()
    
    def validate(self, attrs):
        token = attrs.get("token")
        reset_token = ResetToken.objects.filter(token=token, used=False).first()
        
        if not reset_token:
            raise serializers.ValidationError("Invalid token")
        
        if reset_token.is_expired():
            raise serializers.ValidationError("Token has expired")
        
        attrs["reset_token"] = reset_token
        return attrs
    
    


class PasswordResetCompleteSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=6)
    
    
    def validate(self, attrs):
        token = attrs.get("token")
        new_password = attrs.get("new_password")

        reset_token = ResetToken.objects.filter(token=token, used=False).first()
        
        if not reset_token:
            raise serializers.ValidationError("Invalid token")
        
        if reset_token.is_expired():
            raise serializers.ValidationError("Token has expired")
        
        attrs["reset_token"] = reset_token
        attrs["user"] = reset_token.user
        return attrs
    
    
    def save(self):
        reset_token = self.validated_data["reset_token"]
        user = self.validated_data["user"]
        new_password = self.validated_data["new_password"]
        
        user.set_password(new_password)
        user.save()
        
        reset_token.mark_used()
        
        return user
    
    
    

def create_email_verification_token(user):
    token = generate_reset_token()
    verification = VerificationToken.objects.create(
        user=user,
        token=token,
        expires_at=timezone.now() + timedelta(hours=24)
    )
    return verification




class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    
    def validate(self, attrs):
        token = attrs.get("token")
        verification = VerificationToken.objects.filter(token=token, used=False).first()
        
        if not verification:
            raise serializers.ValidationError("Invalid or expired token")
        
        if verification.is_expired():
            raise serializers.ValidationError("Token as expired")
        
        attrs["verification"] = verification
        attrs["user"] = verification.user
        return attrs
    
    
    def save(self):
        user = self.validated_data["user"]
        verification = self.validated_data["verification"]
        
        user.is_active = True
        user.save()
        
        verification.mark_used()
        
        return user
    
    
