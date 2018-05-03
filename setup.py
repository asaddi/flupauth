import sys

# Sigh... better way?
oid_version = sys.version_info.major == 2 and 'python-openid>=2.2.5' or \
              'python3-openid>=3.1.0'

from setuptools import setup, find_packages
setup(
    name='flupauth',
    version='0.2',
    packages=find_packages(),
    install_requires=[
        'six>=1.11.0',
    ],
    extras_require={
        'oidc': ['openid-connect>=0.4.2mod'],
        'steam': [oid_version, 'Jinja2>=2.10'],
    },

    author='Allan Saddi',
    author_email='allan@saddi.com',
    description='WSGI middleware for a select few SSO-like authentication schemes'
)
