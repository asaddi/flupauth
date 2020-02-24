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

import time

from ._utils import generate_nonce


__all__ = ['AuthInfoService']


# Using JWT is also a possibility. But we'll go with this for now.
# In essence, iss/aud = app_id, sub = username. Also makes use of iat and jti.
# Note that we don't bother with signing/encryption because we assume
# any sane client-side session implementation will do that already.
# So JWT might actually be overkill...
class AuthInfoService(object):

    def __init__(self, app_id, global_ttl=None):
        self._app_id = app_id
        self._global_ttl = global_ttl

    def issue(self, username):
        now = int(time.time())
        auth_info = (username, self._app_id, now, generate_nonce(22))
        self._register(auth_info)
        return auth_info

    def is_valid(self, auth_info):
        return auth_info[1] == self._app_id and \
            (self._global_ttl is None or auth_info[2] + self._global_ttl >= time.time()) and \
            self._is_allowed(auth_info)

    def _register(self, auth_info):
        # May want to build a whitelist, in which case you'd store it
        # server-side here.
        pass

    def _is_allowed(self, auth_info):
        # Check the whitelist or alternatively, check the blacklist.
        # Also possible: per-user expiration to check timestamp against.
        # Default implementation does nothing.
        return True
