import os
import string
import time

from base64 import urlsafe_b64encode

try:
    from urllib.parse import quote, urlencode, parse_qsl
except ImportError:
    # Python 2.x
    from urllib import quote, urlencode
    from cgi import parse_qsl

from openid_connect import OpenIDClient


__all__ = ['OpenIDConnectMiddleware', 'OIDC_AUTH_INFO_KEY']


# Session keys
OIDC_AUTH_INFO_KEY = 'oidc.auth_info'
OIDC_STATE = 'oidc.state'


def get_base_url(environ):
    """Reconstructs request URL from environ, sans path info/query string."""
    url = environ['wsgi.url_scheme'] + '://'

    if environ.get('HTTP_HOST'):
        url += environ['HTTP_HOST']
    else:
        url += environ['SERVER_NAME']

        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
                url += ':' + environ['SERVER_PORT']

    url += quote(environ.get('SCRIPT_NAME',''))

    return url


def get_original_url(environ):
    """Reconstructs request URL from environ, sans query string."""
    url = get_base_url(environ)
    url += quote(environ.get('PATH_INFO',''))

    return url


def generate_nonce(byte_length):
    return urlsafe_b64encode(os.urandom(byte_length)).rstrip('=')


# Using the JWT as-is is also a possibility. But we'll go with this for now.
# In essence, aud = app_id, sub = username. Also makes use of iat and jti.
class AuthInfoService(object):

    NONCE_LENGTH = 22

    def __init__(self, app_id=None):
        if app_id is None:
            # Just make one up.
            # This also means any prior auth infos handed out will now be invalid.
            # Probably not what you want in production.
            app_id = generate_nonce(12)
        self._app_id = app_id

    def issue(self, username):
        now = int(time.time())
        auth_info = (username, self._app_id, now, generate_nonce(16))
        self._register(auth_info)
        return auth_info

    def is_valid(self, auth_info):
        return auth_info[1] == self._app_id and self._is_allowed(auth_info)

    def _register(self, auth_info):
        # May want to build a whitelist, in which case you'd store it server-side here.
        pass

    def _is_allowed(self, auth_info):
        # Check the whitelist or alternatively, check the blacklist.
        # Default implementation does nothing.
        return True


class OpenIDConnectMiddleware(object):

    def __init__(self, application, url, client_id=None, client_secret=None,
                 username_key='sub', login_path='/login', default_path='/',
                 auth_info_service=None, app_id=None):
        self._application = application
        self._username_key = username_key
        self._login_path = login_path
        self._default_path = default_path

        if auth_info_service is None:
            self._auth_info_service = AuthInfoService(app_id)

        # TODO periodically time out and refresh the client so
        # the configuration doesn't become stale.
        self._client = OpenIDClient(url, client_id=client_id,
                                    client_secret=client_secret)

    def __call__(self, environ, start_response):
        session = self._get_session(environ)
        path_info = environ.get('PATH_INFO', '')
        if OIDC_AUTH_INFO_KEY in session:
            # Possibly already authenticated
            auth_info = session[OIDC_AUTH_INFO_KEY]
            if self._auth_info_service.is_valid(auth_info):
                if path_info == self._login_path:
                    # Just redirect to default if they try to hit the login page
                    start_response('302 Moved Temporarily', [
                        ('Location', get_base_url(environ) + self._default_path)
                    ])
                    return []
                # Update environ and pass through to application
                environ['AUTH_TYPE'] = 'OIDC'
                environ['REMOTE_USER'] = str(auth_info[0])
                return self._application(environ, start_response)

        # Not yet authenticated...

        # If it's our login path, handle that elsewhere.
        if path_info == self._login_path:
            return self._login(environ, start_response)

        # Otherwise, redirect to OpenID provider
        state = generate_nonce(8)
        session[OIDC_STATE] = (get_original_url(environ), state)
        self._save_session(environ)
        url = self._client.authorize(get_base_url(environ) +
                                     self._login_path, state=state)
        start_response('302 Temporarily Moved', [
            ('Location', url)
        ])
        return []

    def _login(self, environ, start_response):
        session = self._get_session(environ)
        params = dict(parse_qsl(environ.get('QUERY_STRING', '')))
        if OIDC_STATE in session and 'code' in params and 'state' in params:
            # An expected return from OpenID provider
            success = False
            state = params['state']
            return_to, expected_state = session[OIDC_STATE]
            del session[OIDC_STATE]
            try:
                if state == expected_state:
                    token_response = self._client.request_token(get_base_url(environ) + self._login_path, params['code'])
                    id_token = self._client.get_id(token_response)

                    session[OIDC_AUTH_INFO_KEY] = self._auth_info_service.issue(id_token[self._username_key])
                    success = True
            finally:
                self._save_session(environ)

            if success:
                start_response('302 Moved Temporarily', [
                    ('Location', return_to)
                ])
                return []

            # Otherwise, fall through...

        # Bad request
        start_response('400 Bad Request', [])
        return ['Bad Request\n']

    def _get_session(self, environ):
        return environ['flup.session']()

    def _save_session(self, environ):
        pass
