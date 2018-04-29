import random
import string

try:
    from urllib.parse import quote, urlencode, parse_qsl
except ImportError:
    # Python 2.x
    from urllib import quote, urlencode
    from cgi import parse_qsl

from openid_connect import OpenIDClient


__all__ = ['OpenIDConnectMiddleware', 'OIDC_USERNAME_KEY']


# Session keys
OIDC_USERNAME_KEY = 'oidc.username'
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


NONCE_CHARACTERS = string.ascii_letters + string.digits + '-_'
nonce_random = random.SystemRandom()


def generate_nonce():
    c = [nonce_random.choice(NONCE_CHARACTERS) for x in range(11)]
    return ''.join(c)


class OpenIDConnectMiddleware(object):

    def __init__(self, application, url, client_id=None, client_secret=None,
                 username_key='sub', login_path='/login', default_path='/'):
        self._application = application
        self._username_key = username_key
        self._login_path = login_path
        self._default_path = default_path
        # TODO periodically time out and refresh the client so
        # the configuration doesn't become stale.
        self._client = OpenIDClient(url, client_id=client_id,
                                    client_secret=client_secret)

    def __call__(self, environ, start_response):
        session = self._get_session(environ)
        path_info = environ.get('PATH_INFO', '')
        if OIDC_USERNAME_KEY in session:
            # Already authenticated
            if path_info == self._login_path:
                # Just redirect to default if they try to hit the login page
                start_response('302 Moved Temporarily', [
                    ('Location', get_base_url(environ) + self._default_path)
                ])
                return []
            # Update environ and pass through to application
            environ['AUTH_TYPE'] = 'OIDC'
            environ['REMOTE_USER'] = session[OIDC_USERNAME_KEY]
            return self._application(environ, start_response)
        else:
            # If it's our login path, handle that elsewhere.
            if path_info == self._login_path:
                return self._login(environ, start_response)

            # Otherwise, redirect to OpenID provider
            state = generate_nonce()
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

                    session[OIDC_USERNAME_KEY] = str(id_token[self._username_key])
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
