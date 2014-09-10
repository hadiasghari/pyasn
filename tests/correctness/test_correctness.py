__author__ = 'arman'

from unittest import TestCase

import tests.resources.resources as RES
import pyasn
import pickle
import functools


class TestCorrectness(TestCase):

    def setUp(self):
        self.asndb = pyasn.pyasn(RES.IPASN_DB_PATH)

    def _check_static_map(self):
        """
            Checks if the current pyasn returns the same AS number as
            the static mapping provided in test resources.
        """
        with open(RES.STATIC_WHOIS_MAPPING_PATH, "rb") as f:
            static_mapping = pickle.load(f)
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
        with open(RES.STATIC_OLD_PYASN_MAPPING_PATH, "r") as f:
            static_mapping = eval(functools.reduce(lambda x, y: x+y, f.readlines()))
            self.assrtTrue(len(static_mapping) > 0,
                           msg="Failed to Load RESOURCE.static.map! Resource was not found or was empty.")
            for ip in static_mapping:
                pyasn = self.asndb.lookup_asn(ip)
                old_pyasn = static_mapping[ip]
                self.assertEqual(pyasn, old_pyasn)


# whois -h whois.cymru.com " -f 216.90.108.31 2005-12-25 13:23:01 GMT"




