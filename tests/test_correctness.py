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
import gzip
import pickle

from unittest import TestCase
import pyasn
import os
from struct import pack, unpack
from socket import inet_aton, inet_ntoa
import logging

FAKE_IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn.fake")
IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn_20140513.dat")
STATIC_WHOIS_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "../data/cymru.map")
STATIC_OLD_PYASN_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "../data/pyasn_v1.2__ipasn_20140513__sample_10000.pickle.gz")
logger = logging.getLogger()

class TestCorrectness(TestCase):

    asndb = pyasn.pyasn(IPASN_DB_PATH)
    asndb_fake = pyasn.pyasn(FAKE_IPASN_DB_PATH)

    def test_consistency(self):
        """
            Checks if pyasn is consistently loaded and that it returns a consistent answer
        """
        db = pyasn.pyasn(IPASN_DB_PATH)
        asn, prefix = db.lookup('8.8.8.8')
        for i in range(100):
            tmp_asn, tmp_prefix = self.asndb.lookup('8.8.8.8')
            self.assertEqual(asn, tmp_asn)
            self.assertEqual(prefix, tmp_prefix)

    def test_correctness(self):
        """
            Checks if pyasn returns the correct AS number
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

    def test_static_map(self):
        """
            Checks if the current pyasn returns closely similar ASNs as a static lookups saved from whois lookups.
        """
        with open(STATIC_WHOIS_MAPPING_PATH, "r") as f:
            static_mapping = eval(f.read())
            self.assertTrue(len(static_mapping) > 0,
                           msg="Failed to Load RESOURCE.static.map! Resource was not found or was empty.")
            # For test output consistency we sort the order in which we check the ips
            difference_count = 0
            for ip in sorted(static_mapping.keys()):
                pyasn_value, prefix = self.asndb.lookup(ip)
                teamcymru_asn_value = static_mapping[ip]
                if pyasn_value != teamcymru_asn_value:
                    difference_count += 1
                self.assert_(difference_count < 100,  msg="Failed for IP %s" % ip)

    def test_compatibility(self):
        """
            Checks if pyasn returns the same AS number as the old version of pyasn.
        """
        f = gzip.open(STATIC_OLD_PYASN_MAPPING_PATH, "rb")
        logger.debug("Loading mapping file ...")
        static_mapping = pickle.load(f)
        self.assertTrue(len(static_mapping) > 0, msg="Failed to Load RESOURCE.static.map! Resource was not found or was empty.")
        logger.debug("Mapping file loaded.")
        same_count, difference_count = (0, 0)
        for nip in sorted(static_mapping.keys()): #For test output consistency we sort the order in which we check the ips
            sip = inet_ntoa(pack('>I', nip))
            pyasn_value, prefix = self.asndb.lookup(sip)
            old_pyasn_value = static_mapping[nip]
            if pyasn_value != old_pyasn_value:
                logger.debug("AS Lookup inconsistent for %s current_pyasn = %s pyasn-v1.2 = %s" % (sip, pyasn_value, old_pyasn_value))
                difference_count += 1
            else:
                same_count += 1
            self.assertEqual(difference_count, 0, msg="Too Many failures!")
        logger.info("same: %d, diff: %d" % (same_count, difference_count))
        f.close()

# whois -h whois.cymru.com " -f 216.90.108.31 2005-12-25 13:23:01 GMT"




