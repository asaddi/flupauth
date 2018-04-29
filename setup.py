from setuptools import setup, find_packages
setup(
    name='oidcmiddleware',
    version='0.2',
    packages=find_packages(),
    install_requires=[
        'six>=1.11.0',
        'openid-connect>=0.4.2'
        ],

    author='Allan Saddi',
    author_email='allan@saddi.com',
    description='Simple WSGI middleware for authenticating against a single OpenID Connect provider',
)
