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

import random
import string

from six.moves.urllib.parse import quote

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
    """Reconstructs request URL from environ."""
    url = get_base_url(environ)
    url += quote(environ.get('PATH_INFO',''))
    if environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']

    return url


def get_original_url_nq(environ):
    """Reconstructs request URL from environ, sans query string."""
    url = get_base_url(environ)
    url += quote(environ.get('PATH_INFO',''))

    return url


_noncechars = string.ascii_letters + string.digits + '-_'
_noncerand = random.SystemRandom()

def generate_nonce(length):
    return ''.join([_noncerand.choice(_noncechars) for _ in range(length)])
