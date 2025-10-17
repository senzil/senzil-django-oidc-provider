"""
User consent management views.
Allows users to view and revoke their granted consents.
"""

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils.translation import gettext as _

from oidc_provider.models import UserConsent, Client


@login_required
def consent_list(request):
    """
    Display list of all consents granted by the user.
    """
    consents = UserConsent.objects.filter(
        user=request.user
    ).select_related('client').order_by('-date_given')
    
    # Annotate with expired status
    for consent in consents:
        consent.is_expired = consent.has_expired()
    
    context = {
        'consents': consents,
        'active_consents': [c for c in consents if not c.is_expired],
        'expired_consents': [c for c in consents if c.is_expired],
    }
    
    return render(request, 'oidc_provider/consent_list.html', context)


@login_required
@require_http_methods(['POST'])
def consent_revoke(request, consent_id):
    """
    Revoke a specific consent.
    """
    consent = get_object_or_404(
        UserConsent, 
        id=consent_id, 
        user=request.user
    )
    
    client_name = consent.client.name
    consent.delete()
    
    messages.success(
        request, 
        _(f'Access for "{client_name}" has been revoked successfully.')
    )
    
    # Return JSON for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'success': True,
            'message': _(f'Access for "{client_name}" has been revoked.')
        })
    
    return redirect('oidc_provider:consent-list')


@login_required
@require_http_methods(['POST'])
def consent_revoke_all(request):
    """
    Revoke all consents for the user.
    """
    count = UserConsent.objects.filter(user=request.user).delete()[0]
    
    messages.success(
        request,
        _(f'Successfully revoked access for {count} application(s).')
    )
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'success': True,
            'count': count,
            'message': _(f'Successfully revoked access for {count} application(s).')
        })
    
    return redirect('oidc_provider:consent-list')


@login_required
def consent_detail(request, consent_id):
    """
    View details of a specific consent.
    """
    consent = get_object_or_404(
        UserConsent,
        id=consent_id,
        user=request.user
    )
    
    # Get scope information
    from oidc_provider.lib.claims import StandardScopeClaims
    from oidc_provider import settings as oidc_settings
    
    scopes_info = StandardScopeClaims.get_scopes_info(consent.scope)
    
    if oidc_settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
        extra_scopes = oidc_settings.get(
            'OIDC_EXTRA_SCOPE_CLAIMS', 
            import_str=True
        ).get_scopes_info(consent.scope)
        scopes_info.extend(extra_scopes)
    
    context = {
        'consent': consent,
        'scopes': scopes_info,
        'is_expired': consent.has_expired(),
    }
    
    return render(request, 'oidc_provider/consent_detail.html', context)


@login_required
def consent_app_list(request):
    """
    API endpoint to list consents as JSON.
    """
    consents = UserConsent.objects.filter(
        user=request.user
    ).select_related('client').order_by('-date_given')
    
    data = []
    for consent in consents:
        data.append({
            'id': consent.id,
            'client_id': consent.client.client_id,
            'client_name': consent.client.name,
            'date_given': consent.date_given.isoformat(),
            'expires_at': consent.expires_at.isoformat(),
            'is_expired': consent.has_expired(),
            'scopes': consent.scope,
        })
    
    return JsonResponse({'consents': data})
