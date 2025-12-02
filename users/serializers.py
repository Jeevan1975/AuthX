from rest_framework import serializers
from .models import User
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