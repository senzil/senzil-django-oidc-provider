"""
URL configuration for WebAuthn/Passkey functionality.
"""

try:
    from django.urls import path
except ImportError:
    from django.conf.urls import url as path

from . import views_passkey

urlpatterns = [
    # Passkey Registration
    path('passkey/register/options/', views_passkey.passkey_registration_options, name='passkey-register-options'),
    path('passkey/register/verify/', views_passkey.passkey_registration_verify, name='passkey-register-verify'),
    
    # Passkey Authentication
    path('passkey/auth/options/', views_passkey.passkey_authentication_options, name='passkey-auth-options'),
    path('passkey/auth/verify/', views_passkey.passkey_authentication_verify, name='passkey-auth-verify'),
    
    # Passkey Management
    path('passkey/list/', views_passkey.passkey_list, name='passkey-list'),
    path('passkey/<int:credential_id>/delete/', views_passkey.passkey_delete, name='passkey-delete'),
]
