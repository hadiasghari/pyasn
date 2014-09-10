from __future__ import print_function
import codecs
import sys
import platform

from setuptools import setup, find_packages, Extension
from os.path import abspath, dirname, join

here = abspath(dirname(__file__))

with codecs.open(join(here, 'README.md'), encoding='utf-8') as f:
    README = f.read() 

libs = ['Ws2_32'] if platform.system() == "Windows" else []
ext = Extension('pyasn.pyasn_radix',
              sources=['pyasn/pyasn_radix.c', 'pyasn/_radix/radix.c'],
              include_dirs=[join(here, 'pyasn')],
              libraries=libs)
extra_kwargs = {}
extra_kwargs['ext_modules'] = [ext]

setup(
    name='pyasn',
    version='1.5.0b1',
    maintainer='Hadi Asghari',
    maintainer_email='hd.asghari@gmail.com',
    url='https://github.com/hadiasghari/pyasn',
    description='Python IP address to Autonomous System Number lookup module.',
    long_description=README,
    license='MIT',
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
    keywords='ip asn autonomous system bgp whois prefix radix python routing networking',
    install_requires=[],
    data_files={'pyasn_data': ['data/*.dat']},
    scripts={},
    setup_requires=[],
    tests_require=['nose'],
    packages=find_packages(exclude=['tests', 'tests.*']),
    test_suite='nose.collector',
    **extra_kwargs
)


