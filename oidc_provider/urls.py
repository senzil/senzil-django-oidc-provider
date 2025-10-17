from django.urls import path, re_path
from django.views.decorators.csrf import csrf_exempt

from oidc_provider import (
    settings,
    views,
    views_consent,
    views_registration,
)

app_name = 'oidc_provider'
urlpatterns = [
    re_path(r'^authorize/?$', views.AuthorizeView.as_view(), name='authorize'),
    re_path(r'^token/?$', csrf_exempt(views.TokenView.as_view()), name='token'),
    re_path(r'^userinfo/?$', csrf_exempt(views.userinfo), name='userinfo'),
    re_path(r'^end-session/?$', views.EndSessionView.as_view(), name='end-session'),
    re_path(r'^.well-known/openid-configuration/?$', views.ProviderInfoView.as_view(),
        name='provider-info'),
    re_path(r'^introspect/?$', views.TokenIntrospectionView.as_view(), name='token-introspection'),
    re_path(r'^jwks/?$', views.JwksView.as_view(), name='jwks'),
]

if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
    urlpatterns += [
        re_path(r'^check-session-iframe/?$', views.CheckSessionIframeView.as_view(),
            name='check-session-iframe'),
    ]

# Consent management URLs
urlpatterns += [
    url(r'^consent/?$', views_consent.consent_list, name='consent-list'),
    url(r'^consent/(?P<consent_id>\d+)/?$', views_consent.consent_detail, name='consent-detail'),
    url(r'^consent/(?P<consent_id>\d+)/revoke/?$', views_consent.consent_revoke, name='consent-revoke'),
    url(r'^consent/revoke-all/?$', views_consent.consent_revoke_all, name='consent-revoke-all'),
    url(r'^api/consents/?$', views_consent.consent_app_list, name='consent-api-list'),
]

# Dynamic Client Registration URLs (RFC 7591, RFC 7592)
if settings.get('OIDC_DYNAMIC_CLIENT_REGISTRATION_ENABLE', True):
    urlpatterns += [
        url(r'^register/?$', views_registration.client_registration, name='client-registration'),
        url(r'^register/(?P<client_id>[^/]+)/?$', views_registration.ClientManagementView.as_view(), name='client-management'),
    ]
