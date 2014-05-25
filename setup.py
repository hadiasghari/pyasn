#!/usr/bin/env python

import codecs
import sys
import os
import platform

from setuptools import setup, find_packages, Extension
from os.path import abspath, dirname, join

here = abspath(dirname(__file__))

# determine the python version
IS_PYPY = hasattr(sys, 'pypy_version_info') # todo: what is this?

with codecs.open(join(here, 'README.md'), encoding='utf-8') as f:
    README = f.read() 

# introduce some extra setup_args if Python 2.x
extra_kwargs = {}
if not IS_PYPY: 
    libs = ['Ws2_32'] if platform.system() == "Windows" else []
    ext = Extension('pyasn._radix',
                      sources=['pyasn/_radix.c', 'pyasn/_radix/radix.c'],
                      include_dirs=[join(here, 'pyasn')],
                      libraries=libs)
    extra_kwargs['ext_modules'] = [ext]


    # todo: states: zip_safe flag not set; analyzing archive contents...
    # TODO: update README; double check keywords, etc below
    
setup(
    name='pyasn',  
    version='1.5',
    maintainer='Hadi Asghari', 
    maintainer_email='hd.asghari@gmail.com',
    url='https://github.com/hadiasghari/pyasn',
    description='Python IP address to Autonomous System Number lookup module.',
    long_description=README, 
    license='MIT', 
    keywords='ip asn autonomous system bgp whois prefix radix python routing networking',
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: MIT License', # todo: double check. was BSD, made into MIT
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4', # todo: added by HA, check ??
    ],
    
    # TODO: DECIDE WHETHER TO USE NOSE OR OTHERS; ALSO ADD OURS
    #setup_requires=['nose', 'coverage'],
    packages=find_packages(exclude=['tests', 'tests.*']),
    #test_suite='nose.collector', 
    **extra_kwargs
)
