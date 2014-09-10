#!/usr/bin/env python
from __future__ import print_function
import codecs
import sys
import os
import platform

from setuptools import setup, find_packages, Extension
from os.path import abspath, dirname, join

here = abspath(dirname(__file__))

# determine the python version
IS_PYPY = hasattr(sys, 'pypy_version_info')  # todo: what is this?
assert not IS_PYPY  # not sure what this does, temp


with codecs.open(join(here, 'README.md'), encoding='utf-8') as f:
    README = f.read() 

# introduce some extra setup_args if Python 2.x  # ???

extra_kwargs = {}
libs = ['Ws2_32'] if platform.system() == "Windows" else []  # contains getnameinfo()...
ext = Extension('pyasn.pyasn_radix',
              sources=['source/pyasn_radix.c', 'source/_radix/radix.c'],
              include_dirs=[join(here, 'source')],
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
        'License :: OSI Approved :: MIT License', 
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],    
    tests_require=['nose'],
    packages=find_packages(exclude=['tests', 'tests.*']),
    test_suite='nose.collector',
    **extra_kwargs
)
