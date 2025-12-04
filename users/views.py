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
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken as SimpleRefreshToken
from .auth_helpers import create_token_pair_and_store, rotate_refresh_token
from .utils import hash_refresh_token
from .models import User, RefreshToken as RefreshTokenModel
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from .email_service import send_verification_email



COOKIE_NAME = "refresh"
COOKIE_PATH = "/api/auth/token/refresh/"



class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            verification_token = create_email_verification_token(user)
            
            verification_url = f"{settings.SITE_URL}/api/verify-email/?token={verification_token.token}"
            
            # send email
            send_verification_email(user.email, verification_url)
            
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




class TokenObtainView(APIView):
    """
    POST /api/auth/token/   (login)
    Accepts identifier + password (use your LoginSerializer)
    Returns access JWT in body and sets refresh cookie (HttpOnly).
    """
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        # Prevent login if not active
        if not user.is_active:
            return Response({"detail": "Account not active. Verify your email."}, status=status.HTTP_403_FORBIDDEN)

        # optional: gather device info
        device_info = {
            "ip": request.META.get("REMOTE_ADDR"),
            "user_agent": request.META.get("HTTP_USER_AGENT")
        }

        access_str, refresh_str, refresh_record = create_token_pair_and_store(user, device_info=device_info)

        resp = Response({
            "access": access_str,
            "user": {"id": user.id, "username": user.username, "email": user.email}
        }, status=status.HTTP_200_OK)

        # set cookie
        resp.set_cookie(
            key=COOKIE_NAME,
            value=refresh_str,
            httponly=True,
            secure=not settings.DEBUG,  # ensure secure in production
            samesite="Lax",
            path=COOKIE_PATH,
            max_age=int((refresh_record.expires_at - refresh_record.created_at).total_seconds())
        )
        return resp




class TokenRefreshView(APIView):
    """
    POST /api/auth/token/refresh/
    Reads refresh cookie, validates, rotates, and returns new access + sets new cookie.
    """
    def post(self, request):
        refresh_plain = request.COOKIES.get(COOKIE_NAME)
        if not refresh_plain:
            return Response({"detail": "Refresh token missing"}, status=status.HTTP_401_UNAUTHORIZED)

        # Validate JWT signature and extract claims
        try:
            simple_refresh = SimpleRefreshToken(refresh_plain)
            payload = dict(simple_refresh.payload)
        except:
            # invalid token signature/format
            return Response({"detail": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        jti = payload.get("jti")
        user_id = payload.get("user_id")

        # Try to find DB record by jti
        db_record = RefreshTokenModel.objects.filter(jti=jti).first()

        # If no DB record => possible reuse / token never issued by this server
        if not db_record:
            # Revoke all tokens for potential compromise (best-effort)
            User = get_user_model()
            user = User.objects.filter(pk=user_id).first()
            if user:
                RefreshTokenModel.objects.filter(user=user).update(revoked=True)
            return Response({"detail": "Token reuse or invalid. All sessions revoked."}, status=status.HTTP_401_UNAUTHORIZED)

        # If DB record revoked or expired -> unauthorized
        if db_record.revoked or db_record.is_expired():
            RefreshTokenModel.objects.filter(user_id=db_record.user_id).update(revoked=True)
            return Response({"detail": "Token revoked or expired. Please login again."}, status=status.HTTP_401_UNAUTHORIZED)

        # Compare hashes
        incoming_hash = hash_refresh_token(refresh_plain)
        if incoming_hash != db_record.token_hash:
            # reuse detected: revoke all tokens for user
            RefreshTokenModel.objects.filter(user=db_record.user).update(revoked=True)
            return Response({"detail": "Token reuse detected. All sessions revoked. Please login again."}, status=status.HTTP_401_UNAUTHORIZED)

        # All good -> rotate
        device_info = db_record.device_info or {
            "ip": request.META.get("REMOTE_ADDR"),
            "user_agent": request.META.get("HTTP_USER_AGENT")
        }
        new_access, new_refresh_plain, new_record = rotate_refresh_token(refresh_plain, payload, device_info=device_info)

        # update rotation_count on new_record (optional)
        new_record.rotation_count = db_record.rotation_count + 1
        new_record.save(update_fields=["rotation_count"])

        # mark old revoked (rotate handled in helper but extra safety)
        db_record.revoked = True
        db_record.last_used_at = timezone.now()
        db_record.save(update_fields=["revoked", "last_used_at"])

        resp = Response({"access": new_access}, status=status.HTTP_200_OK)
        resp.set_cookie(
            key=COOKIE_NAME,
            value=new_refresh_plain,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Lax",
            path=COOKIE_PATH,
            max_age=int((new_record.expires_at - new_record.created_at).total_seconds())
        )
        return resp




class LogoutView(APIView):
    """
    POST /api/auth/logout/  -> revoke current refresh token (cookie)
    """
    def post(self, request):
        refresh_plain = request.COOKIES.get(COOKIE_NAME)
        if refresh_plain:
            try:
                simple_refresh = SimpleRefreshToken(refresh_plain)
                jti = simple_refresh["jti"]
                RefreshTokenModel.objects.filter(jti=jti).update(revoked=True)
            except:
                pass

        resp = Response({"detail": "Logged out"}, status=status.HTTP_200_OK)
        # clear cookie
        resp.delete_cookie(COOKIE_NAME, path=COOKIE_PATH)
        return resp




class LogoutAllView(APIView):
    """
    POST /api/auth/logout-all/  -> revoke all tokens for current logged-in user
    Requires Authorization header (access token)
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        RefreshTokenModel.objects.filter(user=user).update(revoked=True)
        resp = Response({"detail": "All sessions revoked"}, status=status.HTTP_200_OK)
        resp.delete_cookie(COOKIE_NAME, path=COOKIE_PATH)
        return resp