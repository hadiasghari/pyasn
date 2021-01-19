# Copyright (c) 2014-2017 Hadi Asghari
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
import codecs
import json
import logging
import os
import pickle
from unittest import TestCase

from pyasn import pyasn, pyasn_radix

FAKE_IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn.fake")
IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn_20140513.dat.gz")
IPASN6_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn6_20151101.dat.gz")
AS_NAMES_FILE_PATH = os.path.join(os.path.dirname(__file__), "../data/asnames.json")
AS_NAMES_COMPRESSED_FILE_PATH = os.path.join(os.path.dirname(__file__), "../data/asnames.json.gz")
logger = logging.getLogger()


class TestSimple(TestCase):
    # Tests loading radix file; a few IPs from TUD raneg; ASN32 (asdots) formats.
    # TODO: write test cases for .get_as_prefixes_effective()

    asndb = pyasn(IPASN_DB_PATH)
    asndb_fake = pyasn(FAKE_IPASN_DB_PATH)

    def test_consistency(self):
        """
            Tests if pyasn is consistently loaded and that it returns a consistent answer
        """
        db = pyasn(IPASN_DB_PATH)
        asn, prefix = db.lookup('8.8.8.8')
        for i in range(100):
            tmp_asn, tmp_prefix = self.asndb.lookup('8.8.8.8')
            self.assertEqual(asn, tmp_asn)
            self.assertEqual(prefix, tmp_prefix)

    def test_correctness(self):
        """
            Tests if pyasn returns the correct AS number with simple data base
        """
        for i in range(4):
            asn, prefix = self.asndb_fake.lookup("1.0.0.%d" % i)
            self.assertEqual(1, asn)
            self.assertEqual("1.0.0.0/30", prefix)
        for i in range(4, 256):
            asn, prefix = self.asndb_fake.lookup("1.0.0.%d" % i)
            self.assertEqual(2, asn)
            self.assertEqual("1.0.0.0/24", prefix)
        for i in range(256):
            asn, prefix = self.asndb_fake.lookup("2.0.0.%d" % i)
            self.assertEqual(3, asn)
            self.assertEqual("2.0.0.0/24", prefix)
        for i in range(128, 256):
            asn, prefix = self.asndb_fake.lookup("3.%d.0.0" % i)
            self.assertEqual(4, asn)
            self.assertEqual("3.0.0.0/8", prefix)
        for i in range(0, 128):
            asn, prefix = self.asndb_fake.lookup("3.%d.0.0" % i)
            self.assertEqual(5, asn)
            self.assertEqual("3.0.0.0/9", prefix)

        asn, prefix = self.asndb_fake.lookup("5.0.0.0")
        self.assertEqual(None, asn)
        self.assertEqual(None, prefix)
        # todo: check that self.ipdb.lookup_asn('300.3.4.4') raises expcetion

    def test_as_number_convert(self):
        """
            Tests for correct conversion between 32-bit and ASDOT number formats for ASNs
        """
        self.assertEqual("AS1.5698", pyasn.convert_32bit_to_asdot_asn_format(71234))
        self.assertEqual("AS2.321", pyasn.convert_32bit_to_asdot_asn_format(131393))
        self.assertEqual("AS65535.0", pyasn.convert_32bit_to_asdot_asn_format(4294901760))
        self.assertEqual("AS65535.65535", pyasn.convert_32bit_to_asdot_asn_format(4294967295))
        self.assertEqual("AS0", pyasn.convert_32bit_to_asdot_asn_format(0))

        self.assertEqual(65536, pyasn.convert_asdot_to_32bit_asn("AS1.0"))
        self.assertEqual(71234, pyasn.convert_asdot_to_32bit_asn("AS1.5698"))
        self.assertEqual(4294967295, pyasn.convert_asdot_to_32bit_asn("AS65535.65535"))
        self.assertEqual(0, pyasn.convert_asdot_to_32bit_asn("AS0"))
        self.assertEqual(131393, pyasn.convert_asdot_to_32bit_asn("AS2.321"))

    def test_get_tud_prefixes(self):
        """
            Tests if correct prefixes are returned for a predetermined AS
        """
        prefixes1 = self.asndb.get_as_prefixes(1128)
        prefixes2 = self.asndb.get_as_prefixes(1128)
        prefixes3 = self.asndb.get_as_prefixes('1128')

        self.assertEqual(set(prefixes1),
                         set(['130.161.0.0/16', '131.180.0.0/16', '145.94.0.0/16']))
        self.assertEqual(prefixes1, prefixes2)  # should cache, and hence return same
        self.assertEqual(prefixes1, prefixes3)  # string & int for asn should return the same

    def test_get_prefixes2(self):
        """
            Tests get_as_prefixes() on a border case (bug report #10)
        """
        # why this border-case is interesting:
        # $ cat ipasn_20141028.dat | grep 13289$
        # 82.212.192.0/18	13289
        # $ cat ipasn_20141028.dat | grep 82.212.192.0
        # 82.212.192.0/18	13289
        # 82.212.192.0/19	29624

        prefixes = self.asndb.get_as_prefixes(13289)
        self.assertEqual(set(prefixes), set(['82.212.192.0/18']))
        prefixes = self.asndb.get_as_prefixes(11018)
        self.assertEqual(set(prefixes), set(['216.69.64.0/19']))

    def test_get_tud_effective_prefixes(self):
        prefixes1 = self.asndb.get_as_prefixes_effective(1128)  # TUDelft AS
        self.assertEqual(set(prefixes1),
                         set(['130.161.0.0/16', '131.180.0.0/16', '145.94.0.0/16']))

    def test_address_family(self):
        """
            Tests if pyasn can determine correct and incorrect IPv4/IPv6 addresses (bug #14)
        """
        # the following should not raise
        asn, prefix = self.asndb.lookup('8.8.8.8')
        asn, prefix = self.asndb.lookup('2001:500:88:200::8')

        # the following should raise
        # note: assertRaisesRegexp doesn't exist on Py 2.6, so we're not checking the exp message
        self.assertRaises(ValueError, self.asndb.lookup, '8.8.8.800')
        self.assertRaises(ValueError, self.asndb.lookup, '2001:500g:88:200::8')

    def test_ipv6(self):
        """
            Tests if IPv6 addresseses are lookedup correctly
        """
        db = pyasn(IPASN6_DB_PATH)
        known_ips = [
            # First three IPs sugested by sebix (bug #14). Confirmed AS on WHOIS
            ('2001:41d0:2:7a6::1', 16276),   # OVH IPv6, AS16276
            ('2002:2d22:b585::2d22:b585', 6939),  # WHOIS states: IPv4 endpoint(45.34.181.133) of
                                                  # a 6to4 address. AS6939 = Hurricane Electric
            ('2a02:2770:11:0:21a:4aff:fef0:e779', 196752),  # TILAA, AS196752
            ('2607:f8b0:4006:80f::200e', 15169),  # GOOGLE AAAA
            ('d::d', None),  # Random unused IPv6
        ]

        for ip, known_as in known_ips:
            asn, prefix = db.lookup(ip)
            self.assertEqual(asn, known_as)

    def test_asnames(self):
        """
            Test functionality of AS Name Lookup.
        """
        db_with_names = pyasn(IPASN_DB_PATH, as_names_file=AS_NAMES_FILE_PATH)
        asn, prefix = db_with_names.lookup('8.8.8.8')
        name = db_with_names.get_as_name(asn)
        self.assertTrue(name.lower().find("google") >= 0, "ASN Name Incorrect! Should be Google")

        name = db_with_names.get_as_name(-1)
        self.assertTrue(name is None, "ASN Name Incorrect! Should be None")

    def test_asnames_compressed(self):
        """
            Test functionality of AS Name Lookup with compressed files
        """
        db_with_names = pyasn(IPASN_DB_PATH, as_names_file=AS_NAMES_COMPRESSED_FILE_PATH)
        asn, prefix = db_with_names.lookup('8.8.8.8')
        name = db_with_names.get_as_name(asn)
        self.assertTrue(name.lower().find("google") >= 0, "ASN Name Incorrect! Should be Google")

        name = db_with_names.get_as_name(-1)
        self.assertTrue(name is None, "ASN Name Incorrect! Should be None")

    def test_assize(self):
        """
            Test AS Size calculation correctness
        """
        size = sum([2 ** (32 - int(px.split('/')[1])) for px in []])  # Check empty prefix list
        self.assertEqual(size, 0)

        size = self.asndb.get_as_size(1133)  # Uni Twente AS which has 1 /16 prefixes
        self.assertEqual(size, 65536)        # Manually Checked.

        size = self.asndb.get_as_size(1128)  # TU-Delft AS which has 3 non overlapping /16 prefixes
        self.assertEqual(size, 196608)       # Double checked with RIPE stat.

        size = self.asndb.get_as_size(1124)  # UVA AS has 3 non-overlapping prefixes (2 /16, 1 /17)
        self.assertEqual(size, 163840)       # Double checked with RIPE stat.

    def test_radix_init_from_string(self):
        """
            Test radix initialization from in memory string
        """
        with open(FAKE_IPASN_DB_PATH, "rt") as f:
            ipasn_str = f.read()
        self.assertEqual(len(ipasn_str.splitlines()), 12)  # fake data has 12 lines
        radix = pyasn_radix.Radix()  # note that pyasn_radix is *internal* & not directly used
        n = radix.load_ipasndb("", ipasn_str)
        self.assertEqual(n, 5)  # and 5 prefixes

        # now test the correctness
        for i in range(4):
            asn, prefix = self.asndb_fake.lookup("1.0.0.%d" % i)
            self.assertEqual(1, asn)
            self.assertEqual("1.0.0.0/30", prefix)
        for i in range(4, 256):
            asn, prefix = self.asndb_fake.lookup("1.0.0.%d" % i)
            self.assertEqual(2, asn)
            self.assertEqual("1.0.0.0/24", prefix)
        for i in range(256):
            asn, prefix = self.asndb_fake.lookup("2.0.0.%d" % i)
            self.assertEqual(3, asn)
            self.assertEqual("2.0.0.0/24", prefix)
        for i in range(128, 256):
            asn, prefix = self.asndb_fake.lookup("3.%d.0.0" % i)
            self.assertEqual(4, asn)
            self.assertEqual("3.0.0.0/8", prefix)
        for i in range(0, 128):
            asn, prefix = self.asndb_fake.lookup("3.%d.0.0" % i)
            self.assertEqual(5, asn)
            self.assertEqual("3.0.0.0/9", prefix)
        asn, prefix = self.asndb_fake.lookup("5.0.0.0")
        self.assertEqual(None, asn)
        self.assertEqual(None, prefix)

    def test_pyasn_from_string(self):
        """
        Test pyasn initialization from in memory string
        """
        with open(FAKE_IPASN_DB_PATH, "rt") as f:
            ipasn_str = f.read()
        self.assertEqual(len(ipasn_str.splitlines()), 12)  # fake data has 12 lines
        n = pyasn(None, ipasn_string=ipasn_str)

        # now test the correctness
        for i in range(4):
            asn, prefix = n.lookup("1.0.0.%d" % i)
            self.assertEqual(1, asn)
            self.assertEqual("1.0.0.0/30", prefix)
        for i in range(4, 256):
            asn, prefix = self.asndb_fake.lookup("1.0.0.%d" % i)
            self.assertEqual(2, asn)
            self.assertEqual("1.0.0.0/24", prefix)
        for i in range(256):
            asn, prefix = self.asndb_fake.lookup("2.0.0.%d" % i)
            self.assertEqual(3, asn)
            self.assertEqual("2.0.0.0/24", prefix)
        for i in range(128, 256):
            asn, prefix = self.asndb_fake.lookup("3.%d.0.0" % i)
            self.assertEqual(4, asn)
            self.assertEqual("3.0.0.0/8", prefix)
        for i in range(0, 128):
            asn, prefix = self.asndb_fake.lookup("3.%d.0.0" % i)
            self.assertEqual(5, asn)
            self.assertEqual("3.0.0.0/9", prefix)
        asn, prefix = self.asndb_fake.lookup("5.0.0.0")
        self.assertEqual(None, asn)
        self.assertEqual(None, prefix)
