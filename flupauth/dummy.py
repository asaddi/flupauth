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
