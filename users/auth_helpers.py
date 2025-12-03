from datetime import timedelta
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken as SimpleRefresh, AccessToken
from .models import RefreshToken as RefreshTokenModel
from .utils import hash_refresh_token, default_refresh_expiry, generate_jti
from django.utils import timezone
from django.contrib.auth import get_user_model


ACCESS_LIFETIME = getattr(settings, "SIMPLE_JWT_ACCESS_LIFETIME", timedelta(minutes=10))
REFRESH_LIFETIME = getattr(settings, "SIMPLE_JWT_REFRESH_LIFETIME", timedelta(days=14))


def create_token_pair_and_store(user, device_info=None):
    """
    Creates access and refresh JWTs, saves hashed refresh to DB, returns (access_str, refresh_str, refresh_record)
    """
    # Create jtis
    access_jti = generate_jti()
    refresh_jti = generate_jti()
    
    # create tokens using SimpleJWT classes
    access = AccessToken()
    access["user_id"] = user.pk
    access["type"] = "access"
    access["jti"] = access_jti
    access.set_exp(from_time=timezone.now(), lifetime=ACCESS_LIFETIME)
    
    refresh = SimpleRefresh()
    refresh["user_id"] = user.pk
    refresh["type"] = "refresh"
    refresh["jti"] = refresh_jti
    refresh.set_exp(from_time=timezone.now(), lifetime=REFRESH_LIFETIME) 
    
    access_str = str(access)
    refresh_str = str(refresh)
    
    # store hashed refresh token
    token_hash = hash_refresh_token(refresh_str)
    refresh_record = RefreshTokenModel.objects.create(
        user=user,
        jti=refresh_jti,
        token_hash=token_hash,
        expires_at=default_refresh_expiry(),
        device_info=device_info or {}
    )
    
    return access_str, refresh_str, refresh_record




def rotate_refresh_token(old_refresh_str, old_payload, device_info=None):
    """
    Given a validated old refresh (string) and payload (e.g., parsed token claims),
    rotate token: create new refresh, persist, revoke old.
    Returns (new_access_str, new_refresh_str, new_record)
    """
    user_id = old_payload.get("user_id")
    old_jti = old_payload.get("jti")
    
    User = get_user_model()
    user = User.objects.filter(pk=user_id).first()
    if not user:
        raise ValueError("User not found")

    # create new token pair
    access_str, refresh_str, refresh_record = create_token_pair_and_store(user, device_info=device_info)
    
    # mark old refresh record revoked
    try:
        old_record = RefreshTokenModel.objects.get(jti=old_jti)
        old_record.revoked = True
        old_record.last_used_at = timezone.now()
        old_record.save(update_fields=["revoked", "last_used_at"])
    except RefreshTokenModel.DoesNotExist:
        pass
    
    return access_str, refresh_str, refresh_record
    
