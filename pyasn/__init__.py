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
from collections import defaultdict
from .pyasn_radix import Radix
import re
from ._version import __version__


class pyasn(object):  
    """
    A class that does fast offline historical Autonomous System Number lookups based on IPv4 addresses.
    IPv6 support is under development.
    """

    def __init__(self, ip_asn_db_file, as_names_file=None, binary=False):
        """
        Creates a new instance of pyasn.\n
        :param ip_asn_db_file:
            Filename of the IP-ASN-database to load
            The database can be a simple text file with lines of "NETWORK/BITS\tASN"
            You can create database files from BGP-MRT-dumps using the mrtx and pyasn-utils scripts
            provided alongside the pyasn package. Alternatively you cna download prebuilt database
            from the pyasn homepage.
        :param as_names_file:
            if given, loads autonomous system names from this file (under construction, do not use)
        :param binary:
            set to True if ip_to_asn_file is in binary format, faster but only IPv4 support (under construction, do not use)
        """
        if binary:
            raise Exception("Not Implemented")
        self.radix = Radix()
        # we uses functionality provided by the underlying RADIX class (implemented in C for speed);
        # actions such as add and delete nodes can be run on the radix tree if required - that's why its exposed
        self._ipasndb_file = ip_asn_db_file
        self._asnames_file = as_names_file
        self._binary = binary
        self._records = self.radix.load_ipasndb(ip_asn_db_file, binary=binary)
        self._asnames = self._read_asnames() if as_names_file else None
        self._as_prefixes = None

    def _read_asnames(self):
        """
        Under Construction, Do not use!\n
        reads autonomous system names, if present from both the text and  binary db formats
        """
        raise Exception("Not implemented")
        # todo: test a variety of formats for fastest performance in loading & disc size
        #           - a text file with ASN & AS-NAMES
        #           - gzip of above
        #           - "anydbm"
        #           -  even pickle & compress
        # todo: how should the as-names file be stored for binary format? (one implementation already in pyhelper for this)

    def lookup(self, ip_address):
        """
        Returns the as number and best matching prefix for given ip address.\n
        :param ip_address: String representation of ip address , for example "8.8.8.8".
        :raises: ValueError if an invalid IP address is passed.
        :return: (asn, prefix) of a given IP address.\n
            'asn' is the 32-bit AS Number that holds this IP address, as advertised on BGP.\n
            'prefix' is the best matching prefix in the BGP table for the given IP address.\n
            Returns (None, None) if the IP address is not found (=not advertised, unreachable)
        """
        rn = self.radix.search_best(ip_address)
        return (rn.asn, rn.prefix) if rn else (None, None)

    def get_as_prefixes(self, asn):
        """ :return: All prefixes advertised by given ASN """
        if not self._as_prefixes:
            # build full dictionary of {asn: set(prefixes)}, and cache it for subsequent calls
            self._as_prefixes = defaultdict(set)
            for px in self.radix.prefixes():
                a = self.lookup(px.split('/')[0])[0]
                self._as_prefixes[a].add(px)
        #
        return self._as_prefixes[int(asn)] if int(asn) in self._as_prefixes else None

    def get_as_name(self, asn):
        """
        Under construction, do not use!\n
        :param asn: 32-bit ASN
        :return: the AS-Name associated with this ASN
        """
        raise Exception("Not Implemented")
        if not self._asnames:
            raise Exception("autonomous system names not loaded during initialization")  # todo: or none?
        return self._asnames.get(asn, "???")                  

    def __repr__(self):
        return "pyasn(ipasndb:'%s'; asnames:'%s') - %d prefixes" % (self._ipasndb_file, self._asnames_file, self._records)


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

    @staticmethod
    def convert_32bit_to_asdot_asn_format(asn):
        """
        Converts a 32bit AS number into the ASDOT format AS[Number].[Number] - see rfc5396.\n
        :param asn: The number of an AS in numerical format.
        :return: The AS number in AS[Number].[Number] format.
        """
        div, mod = divmod(asn, 2**16)
        return "AS%d.%d" % (div, mod) if div > 0 else "AS%d" % mod

    @staticmethod
    def convert_asdot_to_32bit_asn(asdot):
        """
        Converts a asdot representation of an AS to a 32bit AS number - see rfc5396.\n
        :param asdot:  "AS[Number].[Number]" representation of an autonomous system
        :return: 32bit AS number
        """
        pattern = re.compile("^[AS]|[as]|[aS]|[As]][0-9]*(\.)?[0-9]+")
        match = pattern.match(asdot)
        if not match:
            raise ValueError("Invalid asdot format for input. input format must be something like AS<Number> or AS<Number>.<Number> ")
        if asdot.find(".") > 0:  # asdot input is of the format AS[d+].<d+> for example AS1.234
            s1, s2 = asdot.split(".")
            i1 = int(s1[2:])
            i2 = int(s2)
            asn = 2**16 * i1 + i2
        else:
            asn = int(asdot[2:])  # asdot input is of the format AS[d+] for example AS123
        return asn