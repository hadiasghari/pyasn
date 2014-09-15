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
from struct import pack
from socket import inet_ntoa
import logging
from sys import stderr

IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn_20140513.dat")
STATIC_WHOIS_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "../data/cymru.map")
STATIC_PYASN_v1_2_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "../data/pyasn_v1.2__ipasn_20140513__sample_10000.pickle.gz")
logger = logging.getLogger()


class TestCorrectness(TestCase):
    asndb = pyasn.pyasn(IPASN_DB_PATH)

    def test_static_map(self):
        """
            Checks if the current pyasn returns closely similar ASNs as a static lookups saved from whois lookups.
        """
        with open(STATIC_WHOIS_MAPPING_PATH, "r") as f:
            static_mapping = eval(f.read())
            self.assertTrue(len(static_mapping) > 0,
                           msg="Failed to Load cymru.map! Test resource not found or empty.")
            difference_count = 0
            for ip in sorted(static_mapping.keys()):  # For output consistency sort the order in which we check the ips
                a, prefix = self.asndb.lookup(ip)
                b = static_mapping[ip]
                if a != b:
                    difference_count += 1
                    #print("%-15s > cymru: %6s, pyasn: %6s" % (ip, b, a), file=stderr)  # todo: print this in file
                self.assertTrue(difference_count < 30,  msg="Failed for >%d cases" % difference_count)

    def test_compatibility(self):
        """
            Checks if pyasn returns the same AS number as the old version of pyasn.
        """
        f = gzip.open(STATIC_PYASN_v1_2_MAPPING_PATH, "rb")
        logger.debug("Loading mapping file ...")
        old_mapping = pickle.load(f)
        self.assertTrue(len(old_mapping) > 0,
                        msg="Failed to Load pyasn_v1.2__ipasn_20140513__sample_10000.pickle.gz!"
                            + " Test resource not found or empty.")
        logger.debug("Mapping file loaded.")
        same, diff = (0, 0)

        for nip in sorted(old_mapping.keys()):  # For output consistency we sort the order in which we check the ips
            sip = inet_ntoa(pack('>I', nip))
            asn, prefix = self.asndb.lookup(sip)
            old_asn = old_mapping[nip]
            if asn != old_asn:
                logger.debug("AS Lookup inconsistent for %s current_pyasn = %s pyasn-v1.2 = %s" % (sip, asn, old_asn))
                diff += 1
            else:
                same += 1
            self.assertEqual(diff, 0, msg="Too Many failures!")
        logger.info("same: %d, diff: %d" % (same, diff))
        f.close()

# whois -h whois.cymru.com " -f 216.90.108.31 2005-12-25 13:23:01 GMT"
