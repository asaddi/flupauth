from setuptools import setup, find_packages
setup(
    name='flupauth',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'six>=1.11.0',
    ],
    extras_require={
        'oidc': ['openid-connect>=0.4.3aps'],
    },

    author='Allan Saddi',
    author_email='allan@saddi.com',
    description='WSGI middleware for a select few SSO-like authentication schemes'
)
