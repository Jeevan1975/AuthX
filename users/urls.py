from django.urls import path
from .views import (
    RegisterView, 
    LoginView, 
    PasswordResetRequestView, 
    PasswordResetValidateView,
    PasswordResetCompleteView,
    VerifyEmailView,
    TokenObtainView,
    TokenRefreshView,
    LogoutView,
    LogoutAllView
)


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/validate/', PasswordResetValidateView.as_view(), name='password-reset-validate'),
    path('password-reset/complete/', PasswordResetCompleteView.as_view(), name='password-reset-complete'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('auth/token/', TokenObtainView.as_view(), name='token-obtail'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/logout/all/', LogoutAllView.as_view(), name='logout-all'),
]
