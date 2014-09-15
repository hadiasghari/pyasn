pyasn
========

.. image:: https://pypip.in/v/pyasn/badge.png
   :target: https://pypi.python.org/pypi/pyasn
    
.. image:: https://pypip.in/d/pyasn/badge.png
   :target: https://pypi.python.org/pypi/pyasn

   
pyasn is a Python extension module that enables you to perform very fast IP address to 
Autonomous System Number lookups. Current state and Historical lookups can be done, 
based on the BGP / MRT file used as input. 

pyasn is different from other as/asn lookup tools in that it providers offline historical lookups.
It providers utility scripts for users to build their own offline historical DBs based on the BGP /MRT
files. This will make pyasn much faster than online dig/whois/json lookups.

The module code is written in C and cross-compiles on both Windows (MSVC) and Linux.   
Underneath it uses a RADIX tree data structure for storage of IP addresses. 
In the current version, it borrows code from py-radix to support both IPv4 and IPv6 network prefixes.
 
This beta release provides support for python 2 and 3. Adds the prefix lookup functionality, some performance
improvements and adds unit tests.
IPv6 support is under construction and will be provided after beta testing is completed.

Package Structure
-----------------

The main portions of the directory tree are as follows: ::

    .
    ├── pyasn/__init__.py       # Python code of the main pyasn module
    ├── pyasn/pyasn_radix.c     # C extension code (Python RADIX module with bulk load)
    ├── pyasn/_radix/*          # C extension code (Based on original RADIX code from MRTd)
    ├── pyasn/mrtx.py           # python module used to convert MRT files to pyasn DB files
    ├── pyasn-utils/*.py        # Scripts to convert BGP MRT dumps to IPASN databases
    ├── data/                   # Test Resources and some sample DBs to use
    ├── tests/                  # Tests 
    └── setup.py                # Standard setup.py for installation/testing/etc.


Installation
------------

Installation is a breeze via pip:

    pip install pyasn

Or with the standard Python:

	python setup.py build
	python setup.py install
	
You will need to have pip, setuptools and build essentials installed 
if you build the package manually. On Ubuntu/Debian you will need to 
run the following command:

    sudo apt-get install python-pip python-dev build-essential
	

Building the C module on Windows requires Microsoft Visual Studio 2010 to be installed.
(It's easiest to use the same Visual Studio version as the on used to build your Python binaries; 
VS Express versions work fine. Older/newer versions, as well as Cygwin or Anaconda work with minor
modifications).

    
Tests are in the ``tests/`` directory and can be run with:

    python setup.py tests


Removing OLD Versions
---------------------

To uninstall the old PyASN, delete the following files from your Python installation:
 
    PYTHONDIR/dist-packages/PyASN.so
    PYTHONDIR/dist-packages/PyASN-1.2.egg-info


Usage
-----

A simple example that demonstrates most of the features: ::

	import pyasn

	# Initialize module and load IP to ASN database
    # the sample database can be found in tests directory
    asndb = pyasn.pyasn('ipasn_20140513.dat')  
    
	asndb.lookup_asn('8.8.8.8')
    # should return: (15169, '8.8.8.0/24')
    


pyasn DB files
--------------
pyasn DB files are a long list of CIDRs used to lookup AS number for IPs. An excerpt from a pyasn db file looks like this:

    ; IP-ASN32-DAT file
    ; Original file : <Path to a rib file>
    ; Converted on  : Tue May 13 22:03:05 2014
    ; CIDRs         : 512490
    ; 
    1.0.0.0/24	15169
    1.0.128.0/17	9737
    1.0.128.0/18	9737
    1.0.128.0/19	9737
    1.0.129.0/24	23969
    ...
    ...
    ...
    

pyasn DB files can be direcly downloaded from the pyasn home #TODO:provide a link for download. 

Alternatively you can also create your own historical record by downloading the RIB-MRT dumps 
from RouteViews, or using the ``pyasn_wget_rib.py`` utility script and convert the dump to a ipasndb 
with the ``pyasn_convert_rib.py`` file.

    
Performance Tips
----------------
Loading of a pyasn db file is the most heavy operation of the package. For fast lookups using different 
multiple pyasn db files (e.g. historical lookups from multiple dates) we recommend caching of loaded 
db files for better performance.
 
Alternatively you can also convert the dbs files to binary format and load them using the binary load option
which improves db load time (beta testing). You can convert db files to binary format using the ``pyasn_dat_to_bin.py`` 
utility script 

License
-------

pyasn is licensed under a MIT license.

It extends code from py-radix (Michael J. Schultz and Damien Miller), 
most notably lowering memory usage and adding a bulk prefix/asn load.
The underlying radix tree implementation is taken (and modified) from MRTd.
These are all subject to BSD licenses. 
See the LICENSE_pyradix_orig file for details.


Contributing
------------

Please report bugs via GitHub at https://github.com/hadiasghari/pyasn

Testing
-------
This beta release has been tested under python version 2.6 & 2.7 and 3.4.
We would appreciate contributions towards testing the pyasn pacakge! 
Unit Tests are highly appreciated.