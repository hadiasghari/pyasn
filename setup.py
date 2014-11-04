from __future__ import print_function
import codecs
import sys
import platform
import glob
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

extra_kwargs = {'ext_modules': [ext]}
reqs = []
if sys.version_info[0] == 2 and sys.version_info[1] < 7:
    reqs.append('ordereddict')
if sys.version_info[0] == 2:
    reqs.append('backport-ipaddress')


utils = glob.glob('pyasn-utils/*.py')

__version__ = None
exec(open('pyasn/_version.py').read())  # load the actual __version__

setup(
    name='pyasn',
    version=__version__,
    maintainer='Hadi Asghari',
    maintainer_email='hd.asghari@gmail.com',
    url='https://github.com/hadiasghari/pyasn',
    description='Offline IP address to Autonomous System Number lookup module.',
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
    install_requires=reqs,
    data_files=[],
    scripts=utils,
    setup_requires=[],
    tests_require=['nose', 'coverage'],
    packages=find_packages(exclude=['tests', 'tests.*']),
    zip_safe=False,
    test_suite='nose.collector',
    **extra_kwargs
)


