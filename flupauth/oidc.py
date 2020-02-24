# Copyright 2018 Allan Saddi <allan@saddi.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from six import string_types
from six.moves.urllib.parse import parse_qsl

from openid_connect import OpenIDClient

from . import *
from ._utils import *


__all__ = ['OpenIDConnectMiddleware',
           'OIDC_AUTH_INFO_KEY']


# Session keys
OIDC_AUTH_INFO_KEY = 'oidc.auth_info'
OIDC_STATE = 'oidc.state'


class OpenIDConnectMiddleware(object):

    def __init__(self, application, url, client_id=None, client_secret=None,
                 username_key=('sub', 'iss'), login_path='/login', default_path='/',
                 app_id=None, global_ttl=None, auth_info_service=None):
        self._application = application
        self._username_key = username_key
        self._login_path = login_path
        self._default_path = default_path

        if app_id is None:
            # Just make one up.
            # This also means any prior auth infos handed out will now be
            # invalid. Probably not what you want in production.
            app_id = generate_nonce(16)

        if auth_info_service is None:
            auth_info_service = AuthInfoService(app_id, global_ttl=global_ttl)
        self._auth_info_service = auth_info_service

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
                    # Just redirect to default if they try to hit the login
                    # page
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
        state = generate_nonce(11)
        nonce = generate_nonce(11)
        session[OIDC_STATE] = (get_original_url(environ), state, nonce)
        self._save_session(environ)
        url = self._client.authorize(get_base_url(environ) +
                                     self._login_path, state=state,
                                     nonce=nonce)
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
            return_to, expected_state, expected_nonce = session[OIDC_STATE]
            del session[OIDC_STATE]
            try:
                if state == expected_state:
                    token_response = self._client.request_token(get_base_url(environ) + self._login_path, params['code'])
                    id_token = token_response.id

                    if id_token.get('nonce', '') == expected_nonce:
                        username = self._get_username(id_token)
                        session[OIDC_AUTH_INFO_KEY] = self._auth_info_service.issue(username)
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

    def _get_username(self, id_token):
        key = self._username_key
        if isinstance(key, string_types):
            # Single key
            return id_token[key]
        else:
            # Assume it's an iterable
            # Join values together with '@' (most useful for "sub@iss",
            # which is the only unique identifier from default claims).
            return '@'.join([id_token[k] for k in key])

    def _get_session(self, environ):
        return environ['flup.session']()

    def _save_session(self, environ):
        pass
