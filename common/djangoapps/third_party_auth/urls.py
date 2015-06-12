"""Url configuration for the third party auth module."""

from django.conf.urls import include, patterns, url

from .views import inactive_user_view, saml_metadata_view, lti_login_view

urlpatterns = patterns(
    '',
    url(r'^auth/inactive', inactive_user_view),
    url(r'^auth/saml/metadata.xml', saml_metadata_view),
    url(r'^auth/login/(?P<backend>lti)/$', lti_login_view),
    url(r'^auth/', include('social.apps.django_app.urls', namespace='social')),
)
