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
import functools
import os

IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn_20140513.dat")
STATIC_WHOIS_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "../data/cymru.map")
STATIC_OLD_PYASN_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "../data/old_pyasn.map")


class TestCorrectness(TestCase):

    def setUp(self):
        self.asndb = pyasn.pyasn(IPASN_DB_PATH)

    def _check_static_map(self):
        """
            Checks if the current pyasn returns the same AS number as
            the static mapping provided in test resources.
        """
        with open(STATIC_WHOIS_MAPPING_PATH, "r") as f:
            static_mapping = eval(functools.reduce(lambda x, y: x+y, f.readlines()))
            self.assrtTrue(len(static_mapping) > 0,
                           msg="Failed to Load RESOURCE.static.map! Resource was not found or was empty.")
            for ip in static_mapping:
                pyasn = self.asndb.lookup_asn(ip)
                teamcymru_asn = static_mapping[ip]
                self.assertEqual(pyasn, teamcymru_asn)

    def _check_compatibility(self):
        """
            Checks if pyasn returns the same AS number as the old version of pyasn.
        """
        with open(STATIC_OLD_PYASN_MAPPING_PATH, "r") as f:
            static_mapping = eval(functools.reduce(lambda x, y: x+y, f.readlines()))
            self.assrtTrue(len(static_mapping) > 0,
                           msg="Failed to Load RESOURCE.static.map! Resource was not found or was empty.")
            for ip in static_mapping:
                pyasn = self.asndb.lookup_asn(ip)
                old_pyasn = static_mapping[ip]
                self.assertEqual(pyasn, old_pyasn)


# whois -h whois.cymru.com " -f 216.90.108.31 2005-12-25 13:23:01 GMT"




