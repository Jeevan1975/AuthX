from django.shortcuts import render
from .serializers import RegisterSerializer, LoginSerializer, PasswordResetRequestSerializer
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from .models import User



class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = (permissions.AllowAny,)
    
    
    
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