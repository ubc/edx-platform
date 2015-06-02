from social.backends.base import BaseAuth


class LTIAuthBackend(BaseAuth):
    name = 'lti'

    def auth_url(self):
        raise NotImplementedError("This backend cannot initiate login")

    def auth_html(self):
        raise NotImplementedError("This backend cannot initiate login")

    def get_user_details(self, response):
        pass

    def auth_complete(self, *args, **kwargs):
        pass
