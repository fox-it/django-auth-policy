#!/usr/bin/env python

import sys
from setuptools import setup


install_requires = ['Django>=1.5']
if sys.hexversion < 0x02070000:
    install_requires.append('ordereddict>=1.1')


setup(
    name='django-auth-policy',
    version='0.3',
    description='Enforces a couple of common authentication policies for the '
                'Django web framework.',
    author='Fox-IT B.V.',
    license='BSD',
    packages=['django_auth_policy'],
    install_requires=install_requires,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Session',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
