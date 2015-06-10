"""
Extra views required for SSO
"""
from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseServerError, Http404, HttpResponseNotAllowed
from django.views.decorators.csrf import csrf_exempt
from .models import SAMLConfiguration
from social.apps.django_app.utils import psa
from social.utils import setting_name
from social.apps.django_app.utils import load_strategy, load_backend
from social.apps.django_app.views import complete

URL_NAMESPACE = getattr(settings, setting_name('URL_NAMESPACE'), None) or 'social'


def saml_metadata_view(request):
    """
    Get the Service Provider metadata for this edx-platform instance.
    You must send this XML to any Shibboleth Identity Provider that you wish to use.
    """
    if not SAMLConfiguration.is_enabled():
        raise Http404
    complete_url = reverse('social:complete', args=("tpa-saml", ))
    if settings.APPEND_SLASH and not complete_url.endswith('/'):
        complete_url = complete_url + '/'  # Required for consistency
    saml_backend = load_backend(load_strategy(request), "tpa-saml", redirect_uri=complete_url)
    metadata, errors = saml_backend.generate_metadata_xml()

    if not errors:
        return HttpResponse(content=metadata, content_type='text/xml')
    return HttpResponseServerError(content=', '.join(errors))


@csrf_exempt
@psa('{0}:complete'.format(URL_NAMESPACE))
def lti_login_view(request, backend, *args, **kwargs):
    """This is a combination login/complete due to LTI being a one step login"""

    if request.method != 'POST':
        return HttpResponseNotAllowed('POST')

    request.backend.start()
    return complete(request, backend, *args, **kwargs)
