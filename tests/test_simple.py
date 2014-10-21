# Copyright (c) 2009-2014 Hadi Asghari
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

from unittest import TestCase
import pyasn
import os
import logging

FAKE_IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn.fake")
IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn_20140513.dat")
logger = logging.getLogger()


class LoadRadixPickle(TestCase):
    asndb = pyasn.pyasn(IPASN_DB_PATH)
    asndb_fake = pyasn.pyasn(FAKE_IPASN_DB_PATH)

    #TODO: check a few from tud's ranges
    #TODO: Check IPv6  at minimum, manually add/remove from the data
    #TODO: Check a few ASN32 (asdots)
    #TODO: Read and load binary ipasn db.
    #TODO: check as names

    def test_consistency(self):
        """
            Tests if pyasn is consistently loaded and that it returns a consistent answer
        """
        db = pyasn.pyasn(IPASN_DB_PATH)
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
       # todo: check that it raises expcetion
       # self.ipdb.lookup_asn('300.3.4.4')

    def test_as_number_convert(self):
        """
            Tests for correct conversion between 32-bit and ASDOT number formats for Autonomous System numbers.
        """
        self.assertEqual("AS1.5698", pyasn.pyasn.convert_32bit_to_asdot_asn_format(71234))
        self.assertEqual("AS2.321", pyasn.pyasn.convert_32bit_to_asdot_asn_format(131393))
        self.assertEqual("AS65535.0", pyasn.pyasn.convert_32bit_to_asdot_asn_format(4294901760))
        self.assertEqual("AS65535.65535", pyasn.pyasn.convert_32bit_to_asdot_asn_format(4294967295))
        self.assertEqual("AS0", pyasn.pyasn.convert_32bit_to_asdot_asn_format(0))

        self.assertEqual(65536, pyasn.pyasn.convert_asdot_to_32bit_asn("AS1.0"))
        self.assertEqual(71234, pyasn.pyasn.convert_asdot_to_32bit_asn("AS1.5698"))
        self.assertEqual(4294967295, pyasn.pyasn.convert_asdot_to_32bit_asn("AS65535.65535"))
        self.assertEqual(0, pyasn.pyasn.convert_asdot_to_32bit_asn("AS0"))
        self.assertEqual(131393, pyasn.pyasn.convert_asdot_to_32bit_asn("AS2.321"))


    def test_get_tud_prefixes(self):
        """
            Tests if correct prefixes are returned for a predetermined AS
        """
        prefixes1 = self.asndb.get_as_prefixes(1128)
        prefixes2 = self.asndb.get_as_prefixes(1128)
        prefixes3 = self.asndb.get_as_prefixes('1128')

        self.assertEqual(set(prefixes1), set(['130.161.0.0/16', '131.180.0.0/16', '145.94.0.0/16']))  # TUDelft prefixes
        self.assertEqual(prefixes1, prefixes2)  # should cache, and hence return same
        self.assertEqual(prefixes1, prefixes3)  # string & int for asn should return the same