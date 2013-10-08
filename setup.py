#!/usr/bin/env python

from setuptools import setup

package = 'django-auth-policy'

setup(
    name=package,
    version='0.2',
    description='Enforces a couple of common authentication policies for the '
                'Django web framework.',
    author='Fox-IT B.V.',
    license='BSD',
    packages=[package],
    install_requires=['Django>=1.5'],
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
