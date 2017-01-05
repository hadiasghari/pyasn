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

from __future__ import print_function, division
import gzip
import pickle
from unittest import TestCase
import pyasn
from os import path
from struct import pack
from socket import inet_ntoa
import logging
from sys import stderr

IPASN_DB_PATH = path.join(path.dirname(__file__), "../data/ipasn_20140513.dat.gz")
STATIC_CYMRUWHOIS_PATH = path.join(path.dirname(__file__), "../data/cymru.map")
STATIC_PYASNv12_PATH = path.join(path.dirname(__file__),
                                 "../data/pyasn_v1.2__ipasn_20140513__sample_10000.pickle.gz")
logger = logging.getLogger()


class TestCorrectness(TestCase):
    asndb = pyasn.pyasn(IPASN_DB_PATH)

    def test_against_cymru(self):
        """
            Tests if pyasn returns similar ASNs to static lookups saved from Cymru-whois.
        """
        with open(STATIC_CYMRUWHOIS_PATH, "r") as f:
            cymru_map = eval(f.read())
            self.assertTrue(len(cymru_map) > 0,
                            msg="Failed to Load cymru.map! Test resource not found or empty.")
            print(file=stderr)
            diff = 0
            for ip in sorted(cymru_map.keys()):  # For output consistency sort order of IPs
                a, prefix = self.asndb.lookup(ip)
                b = cymru_map[ip]
                if a != b:
                    diff += 1
                    # print("  %-15s > cymru: %6s, pyasn: %6s" % (ip, b, a), file=stderr)
                self.assertTrue(diff < 30,  msg="Failed for >%d cases" % diff)

        print(" Cymru-whois & pyasn differ in %d/%d cases; acceptable.. " % (diff, len(cymru_map)),
              end='', file=stderr)

        # Note, if we wish to extend this test, one could programatically accesses
        # Cymru whois as fullows (- although we have our own function):
        # https://github.com/csirtfoundry/BulkWhois
        # https://github.com/trolldbois/python-cymru-services
        # https://github.com/JustinAzoff/python-cymruwhois
        # Also:
        # whois -h whois.cymru.com " -f 216.90.108.31 2005-12-25 13:23:01 GMT"

    def test_compatibility(self):
        """
            Tests if pyasn returns the same AS number as the old version of pyasn.
        """
        f = gzip.open(STATIC_PYASNv12_PATH, "rb")
        logger.debug("Loading mapping file ...")
        old_mapping = pickle.load(f)
        self.assertTrue(len(old_mapping) > 0,
                        msg="Failed to Load pyasn_v1.2__ipasn_20140513__sample_10000.pickle.gz!"
                            " Test resource not found or empty.")
        logger.debug("Mapping file loaded.")
        same, diff = (0, 0)

        for nip in sorted(old_mapping.keys()):  # For output consistency sort the order of IPs
            sip = inet_ntoa(pack('>I', nip))
            asn, prefix = self.asndb.lookup(sip)
            old_asn = old_mapping[nip]
            if sip in ('128.189.32.228', '209.159.249.194'):
                continue  # skip these as pickle created from a bit older rib file.
            if asn != old_asn:
                logger.debug("AS Lookup inconsistent for %s pyasn = %s pyasn-v1.2 = %s" % (
                             sip, asn, old_asn))
                diff += 1
            else:
                same += 1
            self.assertEqual(diff, 0, msg="Too Many failures!")
        logger.info("same: %d, diff: %d" % (same, diff))
        f.close()
