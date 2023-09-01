pyasn
=====

[![PyPI version](https://badge.fury.io/py/pyasn.svg)](https://badge.fury.io/py/pyasn)


**pyasn** is a Python extension module that enables very fast IP address to Autonomous System Number lookups.
Current state and Historical lookups can be done, based on the MRT/RIB BGP archive used as input.

*pyasn* is different from other ASN lookup tools in that it provides **offline** and **historical** lookups.
It provides utility scripts for users to build their own lookup databases based on any MRT/RIB archive.
This makes *pyasn* much faster than online dig/whois/json lookups.

The module is written in C and Python, and cross-compiles on Linux and Windows. Underneath, it uses a radix tree
data structure for storage of IP addresses. In the current version, it borrows code from *py-radix* to support
both IPV4 and IPV6 network prefixes. Compared to the previous version, it provides
support for Python 2 and 3; adds new functionality, performance improvements, and unit-tests.

*pyasn* has been developed by [Hadi Asghari](https://hadiasghari.com) and
[Arman Noroozian](https://anoroozian.nl/) during their PhD research on cybersecurity measurements. The package is used widely and bugs are fixed quickly.  Please report any bugs via GitHub [issues](https://github.com/hadiasghari/pyasn/issues).


Installation
============
Installation is a breeze via pip: ::

    pip3 install pyasn

Or with the standard Python: ::

    python3 setup.py build
    python3 setup.py install --record log

You will need to have pip, setuptools and build essentials installed if you build the package manually. On
Ubuntu/Debian you can get them using the following command: ::

    sudo apt install python3-pip python3-dev python3-setuptools build-essential

Building the C module on Windows, using either pip or from source, requires Microsoft Visual C++ to be installed.
pyasn has been tested using Visual C++ Express 2010, available freely from Microsoft's website, on both the
official Python 3.4 release and Miniconda3. Other versions of Python, Visual Studio, and Cygwin could also work
with minor modifications.



Usage
=====
A simple example that demonstrates most of the features: ::

    import pyasn

    # Initialize module and load IP to ASN database
    # the sample database can be downloaded or built - see below
    asndb = pyasn.pyasn('ipasn_20140513.dat')

    asndb.lookup('8.8.8.8')
    # should return: (15169, '8.8.8.0/24'), the origin AS, and the BGP prefix it matches

    asndb.get_as_prefixes(1128)
    # returns ['130.161.0.0/16', '131.180.0.0/16', '145.94.0.0/16'], TU-Delft prefixes


IPASN Data Files
================
IPASN data files are a long list of prefixes used to lookup AS number for IPs. An excerpt from such a file looks
like this: ::

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

IPASN data files can be created by downloading MRT/RIB BGP archives from Routeviews (or similar sources),
and parsing them using provided scripts that tail the BGP AS-Path. This can be done simply as follows: ::

    pyasn_util_download.py --latest  # or --latestv46 
    pyasn_util_convert.py --single <Downloaded RIB File> <ipasn_db_file_name>


**NOTE:** These scripts are by default installed to ``/usr/local/bin`` and can be executed directly. If you installed
the package to a user directory (using `--user`), these scripts might not be on the path. In such a case invoke them from 
the directory in which they have been copied (e.g. ``~/.local/bin``).

**New in v1.6:** To save disk space, you can gzip IPASN data files. The load time will be slighlty longer.


Performance Tip
===============
Initial loading of a IPASN data file is the most heavy operation of the package. For fast lookups using multiple
IPASN data files, for instance for historical lookups on multiple dates, we recommend caching of loaded data files
for better performance.


Uninstalling pyasn
==================
You can remove *pyasn* as follows: ::

    pip3 uninstall pyasn


If this command generates an error, update your `pip` package to the latest version first.



Package Structure
=================
The main portions of the directory tree are as follows: ::

    .
    ├── pyasn/__init__.py       # Python code of the main pyasn module
    ├── pyasn/pyasn_radix.c     # C extension code (Python RADIX module with bulk load)
    ├── pyasn/_radix/*          # C extension code (Based on original RADIX code from MRTd)
    ├── pyasn/mrtx.py           # python module used to convert MRT files to pyasn DB files
    ├── pyasn-utils/*.py        # Scripts to download & convert BGP MRT dumps to IPASN databases
    ├── data/                   # Test Resources and some sample DBs to use
    ├── tests/                  # Tests
    └── setup.py                # Standard setup.py for installation/testing/etc.



Testing pyasn Sources
=====================
A number of unit tests are provided in the ``tests/`` directory when downlading from source. The tests can be run using the `pytest` command (`pytest-3` in Ubuntu).  

This release has been tested under python version 2.6, 2.7, and 3.3 to 3.11. We appreciate contributions towards
testing and extending *pyasn*!


License & Acknowledgments
=========================
*pyasn* is licensed under the MIT license.

It extends code from py-radix (Michael J. Schultz and Damien Miller),  and improves upon it in several ways, for
instance in lowering memory usage and adding bulk prefix/origin load. The underlying radix tree implementation is
taken (and modified) from MRTd. These are all subject to their respective licenses.  Please see the LICENSE file
for details.

Thanks to Dr. Chris Lee (of Shadowserver) for proposing the use of radix trees.

A handful of GitHub developers have contributed features and bug fixes to the latest releases.
Many thanks to all of them.
