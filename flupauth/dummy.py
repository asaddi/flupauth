from ._authinfo import *
from ._utils import *


__all__ = ['DummyMiddleware']


DUMMY_AUTH_INFO_KEY = 'dummy.auth_info'


class DummyMiddleware(object):

    def __init__(self, application, username,
                 app_id=None, global_ttl=None, auth_info_service=None):
        self._application = application
        self._username = username

        if app_id is None:
            app_id = generate_nonce(16)

        if auth_info_service is None:
            auth_info_service = AuthInfoService(app_id, global_ttl=global_ttl)
        self._auth_info_service = auth_info_service

    def __call__(self, environ, start_response):
        session = self._get_session(environ)
        if DUMMY_AUTH_INFO_KEY in session:
            # Possibly already authenticated
            auth_info = session[DUMMY_AUTH_INFO_KEY]
            if self._auth_info_service.is_valid(auth_info):
                environ['AUTH_TYPE'] = 'DUMMY'
                environ['REMOTE_USER'] = str(auth_info[0])
                return self._application(environ, start_response)

        # Just authenticate as the designated user and redirect back

        session[DUMMY_AUTH_INFO_KEY] = self._auth_info_service.issue(self._username)
        self._save_session(environ)
        start_response('302 Moved Temporarily', [
            ('Location', get_original_url(environ))
        ])
        return []

    def _get_session(self, environ):
        return environ['flup.session']()

    def _save_session(self, environ):
        pass
