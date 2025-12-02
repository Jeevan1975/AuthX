from rest_framework import serializers
from django.utils import timezone
from .models import User, ResetToken
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