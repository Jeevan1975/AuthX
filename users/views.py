from django.shortcuts import render
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from .models import User



class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = (permissions.AllowAny,)