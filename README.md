py-asn
========

.. image:: https://pypip.in/v/py-asn/badge.png
   :target: https://pypi.python.org/pypi/py-asn
    
.. image:: https://pypip.in/d/py-asn/badge.png
   :target: https://pypi.python.org/pypi/py-asn

   
pyasn is a Python extension module that enables you to perform very fast IP address to 
Autonomous System Number lookups. Historical lookups as well as current lookups can be done, 
based on the BGP / MRT file used as input.

The module code is written in C and cross-compiles on both Windows (MSVC) and Linux.   
Underneath it uses a RADIX tree data structure for storage of IP addresses. In earlier versions,
it used the LIBGDS implementation, and in the current version, it borrows code from py-radix 
to support both IPv4 and IPv6 network prefixes. 



TODO: add following text:
- key comparison point versus other modules is that it provides historical lookups at point in time in past, 
- the files are stored locally, meaning it is much faster than doing dig/whois/json lookups, especially when doing millions of lookups
- project was born out of research conducted at the Economics of Cybersecurity group at Delft University of Technology. (2010-2014)
- Python 2 & 3 supported    
- IPv4 & IPv6 & 32-bit ASN support. (note: IPv6  not fully tested)
    


Installation
------------

Installation is a breeze via pip: ::

    pip install py-asn

Or with the standard Python distutils incantation: ::

	python setup.py build
	python setup.py install

Building the C module on Windows requires Microsoft Visual Studio 2010 to be installed.
(It's easiest to use the same Visual Studio version as the on used to build your Python binaries; 
VS Express versions work fine. Older/newer versions, as well as Cygwin work with minor modifications).

On Ubuntu, you need to have following packages at a minimum installed:
sudo apt-get install python-dev build-essential
    
    
Tests are in the ``tests/`` directory and can be run with
``python setup.py tests``.


Usage
-----

A simple example that demonstrates most of the features: ::

	import pyasn

	# Initialize module and load IP to ASN database
    # the sample database can be found in tests directory
    asndb = pyasn.pyasn('ipasn_20140513.dat')  
    
	asndb.lookup_asn('8.8.8.8')
    # should return: 15169
    
    asndb.lookup_asn_prefix('8.8.8.8')
    # should return: (15169, '8.8.8.0/24')



    # TODO: explain following additional functionality:
    #    -some funcitons of pyasn (.as-name, .prefixes,...)
    #    -where to get ipasndb's:
    #       - premade (will be put weekly on github)
    #       - self build  with pyasn-scripts:
    #          (first, download RIB-MRT dumps from  RouteViews, manually or with pyasn_wget_rib.py
    #           then convert to ipasndb with pyasn_convert_rib.py)
    #    -Performance: caching of the asndb object; 
    #    - binary ipasndbs, and ipasndbs with asnames: using pyasn_db_helper.py
    

License
-------

py-asn is licensed under a MIT license.

It extends code from py-radix (Michael J. Schultz and Damien Miller), 
most notably lowering memory usage and adding a bulk prefix/asn load.
The underlying radix tree implementation is taken (and modified) from MRTd.
These are all subject to BSD licenses. 
See the LICENSE_pyradix_orig file for details.


Contributing
------------

Please report bugs via GitHub at https://github.com/hadiasghari/pyasn

The main portions of the directory tree are as follows: ::

    .
    ├── pyasn/__init__.py       # Python code of the main pyasn module
    ├── pyasn/_radix_wrapper.c  # C extension code (Python RADIX module with bulk load)
    ├── pyasn/_radix/*          # C extension code (Based on original RADIX code from MRTd)
    ├── pyasn-helper/*.py       # Scripts to convert BGP MRT dumps to IPASN databases
    ├── tests/                  # Tests 
    └── setup.py                # Standard setup.py for installation/testing/etc.
