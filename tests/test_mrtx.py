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
import pyasn.mrtx
import bz2
import logging

#IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "../data/ipasn_20140513.dat")
#logger = logging.getLogger()


class ConvertMRTFile(TestCase):
    def test_converter(self):
        """
            Checks if pyasn.mrtx works
        """
        with bz2.BZ2File(argv[2], 'rb') as f:
            dat = pyasn.mrtx.parse_file(f)

        #db = pyasn.pyasn(IPASN_DB_PATH)
        #asn, prefix = db.lookup('8.8.8.8')
        #for i in range(100):
        #    tmp_asn, tmp_prefix = self.asndb.lookup('8.8.8.8')
        #    self.assertEqual(asn, tmp_asn)
        #    self.assertEqual(prefix, tmp_prefix)
        pass



