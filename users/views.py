from django.shortcuts import render
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetValidateSerializer,
    PasswordResetCompleteSerializer,
    EmailVerificationSerializer
)
from .serializers import create_email_verification_token
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from .models import User
from django.conf import settings



class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            verification_token = create_email_verification_token(user)
            
            verification_url = f"{settings.SITE_URL}/api/verify-email/?token={verification_token.token}"
            
            return Response(
                {
                    "message": "User registered successfully. Please verify your email.",
                    "verify_url": verification_url
                },
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
    
class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            
            return Response(
                {
                    "message": "Login successful",
                    "user_id": user.id,
                    "usernam": user.username,
                    "email": user.email
                },
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
    
class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            
            return Response(
                {"message": "If this email exists, a reset link has been sent."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
    
class PasswordResetValidateView(APIView):
    def post(self, request):
        serializer = PasswordResetValidateSerializer(data=request.data)
        
        if serializer.is_valid():
            return Response(
                {"message": "Token is valid"},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    


class PasswordResetCompleteView(APIView):
    def post(self, request):
        serializer = PasswordResetCompleteSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Password reset successfull"},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class VerifyEmailView(APIView):
    def get(self, request):
        token = request.GET.get("token")
        serializer = EmailVerificationSerializer(data={'token': token})
        
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Email verified successfully"},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)