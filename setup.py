#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Amazon Account Access',
    'author': 'sokecillo',
    'url': '',
    'download_url': '',
    'author_email': ['sokecillo@gmail.com'],
    'version': '1.0.0',
    'install_requires': [
        'colorama == 0.4.3', 'argparse ==1.4.0', 'boto == 2.49.0', 'requests == 2.24.0', 'awscli == 1.18.163'
    ],
    'packages': ['awsauth'],
    'scripts': [],
    'name': 'aws-auth',
    'entry_points': {
        'console_scripts': ['awsauth = awsauth.awsauth:Awsauth']
    }
}
setup(**config)
