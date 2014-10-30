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

from __future__ import print_function
from unittest import TestCase
import pyasn
import logging
import sys
from glob import glob
import random

IPASN_DB_PATH = "/data/data/db.rviews/"
logger = logging.getLogger()


class TestPyASNAggresive(TestCase):

    def test_all_ipasn_dbs(self):
        """
            Checks compatibility of PyASN 1.2 results with current pyasn for all 2014 ipasn dbs .
        """
        version = sys.version_info[0]
        try:
            import PyASN
            assert version == 2
        except:
            print("SKIPPING - Python 2 or PyASN 1.2 not present ...", file=sys.stderr, end=' ')
            return

        dbs = glob(IPASN_DB_PATH + "ipasn_2014*.dat")
        print("", file=sys.stderr)
        for db in sorted(dbs):
            random.seed(db)  # for reproducibility
            print("comparing %s" % db, file=sys.stderr)
            newdb = pyasn.pyasn(db)
            olddb = PyASN.new(db)

            for i in range(1000000):
                i1 = random.randint(1, 223)
                i2 = random.randint(0, 255)
                i3 = random.randint(0, 255)
                i4 = random.randint(0, 255)

                sip = "%d.%d.%d.%d" % (i1, i2, i3, i4)
                newas, prefix = newdb.lookup(sip)
                if newas: 
                    self.assertTrue(newas > 0, msg="Negative AS for IP %s = %s" % (sip, newas))  
                oldas = olddb.Lookup(sip)
                if oldas < 0:
                    # this is an overflow bug in the old version, 
                    # e.g. 193.181.4.145 on 2014/10/07 returns -33785576 
                    continue  
                self.assertEqual(oldas, newas, msg="Failed for IP %s" % sip)


