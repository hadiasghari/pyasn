#!/usr/bin/env python
__author__ = 'arman'

from unittest import TestCase
from tests.utilities.functions import *

import tests.resources.resources as RES
import pyasn
import pickle


class TestCorrectness(TestCase):

    _STATIC_MAPPING = {}

    def setUp(self):
        self.asndb = pyasn.pyasn(RES.IPASN_DB_PATH)
        with open(RES.STATIC_MAPPING_PATH, "rb") as f:
            self._STATIC_MAPPING = pickle.load(f)

    def _check_static_map(self):
        """
            Checks if the current pyasn returns the same AS number as
            the static mapping provided in test resources.
        """
        self.assrtTrue(len(self._STATIC_MAPPING) > 0,
                       msg="Failed to Load RESOURCE.static.map! Resource was not found or was empty.")
        for ip in self._STATIC_MAPPING:
            pyasn = self.asndb.lookup_asn(ip)
            teamcymru_asn = as_loopkup_teamcymru(ip, RES.IPASN_DB_DATE)
            self.assertEqual(pyasn, teamcymru_asn)

    def _check_compatibility(self):
        """
            Checks if pyasn returns the same AS number as the old version of pyasn.
        """
        # for ip in self._STATIC_MAPPING:
        #     pyasn = self.asndb.lookup_asn(ip)
        pass



# whois -h whois.cymru.com " -f 216.90.108.31 2005-12-25 13:23:01 GMT"




