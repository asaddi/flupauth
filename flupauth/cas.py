import traceback

from six.moves.urllib.parse import urlencode, parse_qsl

from ._authinfo import *
from ._utils import *
from ._casclient import *


__all__ = ['CASMiddleware',
           'CAS_AUTH_INFO_KEY']


# Session keys
CAS_AUTH_INFO_KEY = 'cas.auth_info'
CAS_SERVICE_KEY = 'cas.service'


class CASMiddleware(object):

    def __init__(self, application, login_url, validate_url, casfailed_url=None,
                 app_id=None, global_ttl=None, auth_info_service=None):
        self._application = application
        self._login_url = login_url
        self._validate_url = validate_url
        self._casfailed_url = casfailed_url

        if app_id is None:
            app_id = generate_nonce(16)

        if auth_info_service is None:
            auth_info_service = AuthInfoService(app_id, global_ttl=global_ttl)
        self._auth_info_service = auth_info_service

    def __call__(self, environ, start_response):
        session = self._get_session(environ)
        if CAS_AUTH_INFO_KEY in session:
            # Possibly already authenticated
            auth_info = session[CAS_AUTH_INFO_KEY]
            if self._auth_info_service.is_valid(auth_info):
                environ['AUTH_TYPE'] = 'CAS'
                environ['REMOTE_USER'] = str(auth_info[0])
                return self._application(environ, start_response)

        # Not yet authenticated...

        params = dict(parse_qsl(environ.get('QUERY_STRING', '')))
        if CAS_SERVICE_KEY in session and 'ticket' in params:
            # Have ticket, validate with CAS server
            ticket = params['ticket']

            service_url = session[CAS_SERVICE_KEY]

            username = None
            cas = CASClient(self._validate_url, service_url)
            try:
                username = cas.authenticate(ticket)
            except:
                traceback.print_exc(file=environ['wsgi.errors'])

            if username is not None:
                # Validation succeeded, redirect back to app
                session[CAS_AUTH_INFO_KEY] = self._auth_info_service.issue(username)
                del session[CAS_SERVICE_KEY]
                self._save_session(environ)
                start_response('302 Moved Temporarily', [
                    ('Location', service_url)
                ])
                return []
            else:
                # Validation failed (for whatever reason)
                return self._casfailed(environ, start_response)
        else:
            # Redirect to CAS login
            service_url = get_original_url(environ)
            # Remember the exact service we're authenticating with
            session[CAS_SERVICE_KEY] = service_url
            self._save_session(environ)
            start_response('302 Moved Temporarily', [
                ('Location',
                 self._login_url + '?' +
                 urlencode({ 'service': service_url }))
            ])
            return []
                    
    def _get_session(self, environ):
        return environ['flup.session']()

    def _save_session(self, environ):
        pass

    def _casfailed(self, environ, start_response):
        if self._casfailed_url is not None:
            start_response('302 Moved Temporarily', [
                ('Location', self._casfailed_url)
                ])
            return []
        else:
            # Default failure notice
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return ['CAS authentication failed\n']
