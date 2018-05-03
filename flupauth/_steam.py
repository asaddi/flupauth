from six.moves.urllib.parse import urlencode, parse_qsl

from openid.consumer import consumer
from openid.store import memstore

from jinja2 import Environment, PackageLoader, select_autoescape

from ._authinfo import *
from ._utils import *


__all__ = ['SteamOpenIDMiddleware',
           'OID2_USERNAME_KEY']


# Session keys
OID2_USERNAME_KEY = 'oid2.username'
# Note the presence of the following is used to determine whether we've
# already redirected to the provider.
OID2_RETURN_TO = 'oid2.return_to'


class SteamOpenIDMiddleware(object):

    _openid_provider = 'https://steamcommunity.com/openid/login'

    def __init__(self, application, login_path='/login', default_path='/'):
        self._application = application
        self._login_path = login_path
        self._default_path = default_path

        self._env = Environment(
            loader=PackageLoader('flupauth', 'templates'),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self._login_page = self._env.get_template('login.html')

    def __call__(self, environ, start_response):
        session = self._get_session(environ)
        path_info = environ.get('PATH_INFO', '')
        if OID2_USERNAME_KEY in session:
            # Already authenticated
            if path_info.startswith(self._login_path):
                # Just redirect to default if they try to hit the login page
                start_response('302 Moved Temporarily', [
                    ('Location', get_base_url(environ) + self._default_path)
                ])
                return []
            # Update environ and pass through to application
            environ['AUTH_TYPE'] = 'OID2'
            environ['REMOTE_USER'] = str(session[OID2_USERNAME_KEY])
            return self._application(environ, start_response)
        else:
            # If it's our login path, handle that elsewhere.
            if path_info.startswith(self._login_path):
                return self._login(environ, start_response)

            # Otherwise, redirect to our login.
            session[OID2_RETURN_TO] = get_original_url(environ)
            self._save_session(environ)
            start_response('302 Moved Temporarily', [
                ('Location', get_base_url(environ) + self._login_path)
            ])
            return []

    def _login(self, environ, start_response):
        session = self._get_session(environ)
        params = dict(parse_qsl(environ.get('QUERY_STRING', '')))
        if 'openid.identity' in params:
            # Returned from OpenID provider
            openid_consumer = consumer.Consumer({}, memstore.MemoryStore())
            info = openid_consumer.complete(params, get_original_url_nq(environ))
            if info.status == consumer.SUCCESS:
                session[OID2_USERNAME_KEY] = params['openid.identity']
                # Figure out where to return to
                if OID2_RETURN_TO in session:
                    return_to = session[OID2_RETURN_TO]
                    del session[OID2_RETURN_TO]
                else:
                    return_to = get_base_url(environ) + self._default_path
                self._save_session(environ)
                start_response('302 Moved Temporarily', [
                    ('Location', return_to)
                    ])
                return []
            else:
                # Authentication failure
                return self._failed(environ, start_response, info.message)
        else:
            # Display login page
            params = {
                'openid.ns': 'http://specs.openid.net/auth/2.0',
                'openid.mode': 'checkid_setup',
                'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.return_to': get_base_url(environ) + self._login_path,
                }
            auth_request_url = self._openid_provider + '?' + urlencode(params)

            start_response('200 OK', [
                ('Content-Type', 'text/html; charset=utf-8')
            ])
            return [self._login_page.render(auth_request_url=auth_request_url)]

    def _get_session(self, environ):
        return environ['flup.session']()

    def _save_session(self, environ):
        pass

    def _failed(self, environ, start_response, message):
        # Default failure notice
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['OpenID authentication failed: {}\n'.format(message)]
