# Copyright (c) 2014 Hadi Asghari
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
TODO: The docstring should list the pyasn() classes, with a one-line summary of it.
 also:   - explain what module is used for, e.g. historical, fast local lookups
         - how to initliaize and lookup - or the object that needs to be called
"""

from .pyasn_radix import Radix

class pyasn(object):  
    """
    TODO: The docstring for a class should summarize its behavior and list the public methods and instance variables.
    """

    def __init__(self, ip_asn_db_file, as_names_file=None, binary=False):
        """
        Creates a new instance of pyasn\n
        ip_asn_db_file
            Filename of the IP-ASN-database to load
            The database can be a simple text file with lines of "NETWORK/BITS\tASN"
            You can create database files using pyasn-helper scripts from BGP-MRT-dumps.
            Or download prebuilt database files from pyasn homepage.
        as_names_file
            if given, loads autonomous system names from this file (slower)
        binary
            set to True if ip_to_asn_file is in binary format (faster but only IPv4 support)
        """
        self.radix = Radix()
        # we uses functionality provided by the underlying RADIX class (implemented in C for speed);
        # actions such as add and delete nodes can be run on the radix tree if required - that's why its exposed
        self._ipasndb_file = ip_asn_db_file
        self._asnames_file = as_names_file
        self._binary = binary
        self._records = self.radix.load_ipasndb(ip_asn_db_file, binary=binary)
        self._asnames = self._read_asnames() if as_names_file else None


    def _read_asnames(self):
        """read autonomous system names, if present from both the text and  binary db formats"""
        raise Exception("Not implemented")
        # todo: test a variety of formats for fastest performance in loading & disc size
        #           - a text file with ASN & AS-NAMES
        #           - gzip of above
        #           - "anydbm"
        #           -  even pickle & compress
        # todo: how should the as-names file be stored for binary format? (one implementation already in pyhelper for this)


    def lookup(self, ip_address):
        """
        Returns (asn, prefix) of a given IP address.\n
        'asn' is the Autonomous System Number that holds this IP address, as advertised on BGP.
        'prefix' is the best matching prefix in the BGP table for this IP address.\n
        Returns (None, None) if the IP address is not found (=not advertised, unreachable)
        Raises ValueError an invalid IP address is passed.
        """
        rn = self.radix.search_best(ip_address)
        return (rn.asn, rn.prefix) if rn else (None, None)


    def get_as_prefixes(self, asn):
        """Returns all Prefixes advertised by this ASN"""
        # note: can build a full dict of {asn: set(prefixes)} on first call, and cache it for subsequent calls to method
        return [px for px in self.radix.prefixes() if self.lookup(px.split('/')[0])[0] == asn]


    def get_as_name(self, asn):
        """Returns the AS-Name for this ASN"""
        if not self._asnames:
            raise Exception("autonomous system names not loaded during initialization")  # todo: or none?
        return self._asnames.get(asn, "???")                  


    def __repr__(self):
        return "pyasn(ipasndb:'%s'; asnames:'%s') - %d prefixes" % (self._ipasndb_file, self._asnames_file, self._records)

    # todo: add two static converter methods to convert ASX.X format into 32bit ASN and vice-versa


    # Persistence support, for use with pickle.dump(), pickle.load()
    # todo: test persistence support.  (also persist/reload _asnames and other members, if not done automatically)
    def __iter__(self):
        for elt in self.radix:
            yield elt
            
    def __getstate__(self):
        return [(elt.prefix, elt.asn) for elt in self]  
        
    def __setstate__(self, state):
        for prefix, asn in state:
            node = self.radix.add(prefix)
            node.asn = asn
            
    def __reduce__(self):
        return Radix, (), self.__getstate__()
