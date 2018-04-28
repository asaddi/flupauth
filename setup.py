from setuptools import setup, find_packages
setup(
    name='oidcmiddleware',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'openid-connect>=0.4.2'
        ],

    author='Allan Saddi',
    author_email='allan@saddi.com',
    description='Simple WSGI middleware for authenticating against a single OpenID Connect provider',
)
