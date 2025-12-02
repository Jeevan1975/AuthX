from django.urls import path
from .views import (
    RegisterView, 
    LoginView, 
    PasswordResetRequestView, 
    PasswordResetValidateView,
    PasswordResetCompleteView
    )


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/validate/', PasswordResetValidateView.as_view(), name='password-reset-validate'),
    path('password-reset/complete/', PasswordResetCompleteView.as_view(), name='password-reset-complete'),
]
