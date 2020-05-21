# coding: utf-8
# python setup.py sdist register upload
from setuptools import setup

setup(
    name='sw-django-rest-auth',
    version='0.0.32',
    description='Soft Way company django restfromework authentication service package.',
    author='Telminov Sergey',
    url='https://github.com/telminov/sw-django-rest-auth',
    packages=[
        'sw_rest_auth',
        'sw_rest_auth/migrations',
        'sw_rest_auth/tests',
    ],
    include_package_data=True,
    license='The MIT License',
    test_suite='runtests.runtests',
    install_requires=[
        'django>=1.8.7',
        'djangorestframework==3.10.3',
        'requests==2.13.0',
        'mock==2.0.0',
    ],
)
