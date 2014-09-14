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
from sys import stderr
from unittest import TestCase
from pyasn.mrtx import *
import bz2
from os import path
import logging

IPASN_DB_PATH = path.join(path.dirname(__file__), "../data/ipasn_20140513.dat")
RIB_FULLDUMP_PATH = path.join(path.dirname(__file__), "../data/rib.20140523.0600.bz2")
RIB_PARTDUMP_PATH = path.join(path.dirname(__file__), "../data/rib.20140523.0600_firstMB.bz2")
#logger = logging.getLogger()


class ConvertMRTFile(TestCase):

    def test_mrt_table_dump_v2(self):
        """
            Tests pyasn.mrtx internal classes by converting start of an RIB TDV2 file
        """
        f = bz2.BZ2File(RIB_PARTDUMP_PATH, 'rb')  # todo: PART

        # first record: TDV2 (13), PEERIX (1)
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP_V2)
        self.assertEqual(mrt.sub_type, MrtRecord.T2_PEER_INDEX_TABLE)
        self.assertEqual(mrt.ts, 1400824800)
        self.assertEqual(mrt.data_len, 619)
        self.assertEqual(mrt.table, None)

        # second record - "0.0.0.0/0" to 16637
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP_V2)
        self.assertEqual(mrt.sub_type, MrtRecord.T2_RIB_IPV4_UNICAST)
        self.assertEqual(mrt.ts, 1400824800)
        self.assertEqual(mrt.data_len, 51)
        self.assertIsInstance(mrt.table, MrtTableDump2)
        self.assertEqual(mrt.table_seq, 0)
        self.assertEqual(mrt.prefix, "0.0.0.0/0")
        self.assertEqual(len(mrt.table.entries), 1)
        entry = mrt.table.entries[0]
        self.assertEqual(entry.attr_len, 36)
        self.assertEqual(entry.peer, 32)
        self.assertEqual(entry.orig_ts, 1399538361)
        self.assertEqual(len(entry.attrs), 4)
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[2].bgp_type, 3)
        self.assertEqual(entry.attrs[3].bgp_type, 4)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertIsInstance(attr.attr_detail, BgpAttribute.BgpAttrASPath)
        path = attr.attr_detail
        self.assertEqual(len(path.pathsegs), 1)
        self.assertEqual(str(path.pathsegs[0]), "[2905, 65023, 16637]")
        self.assertEqual(path.origin_as, 16637)
        self.assertEqual(mrt.as_path, path)

        # third record -
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertIsInstance(mrt.table, MrtTableDump2)
        self.assertEqual(mrt.data_len, 1415)
        self.assertEqual(mrt.table_seq, 1)
        self.assertEqual(mrt.prefix, "1.0.0.0/24")
        self.assertEqual(len(mrt.table.entries), 32)  # wow!
        entry = mrt.table.entries[0]
        self.assertEqual(entry.attr_len, 29)
        self.assertEqual(entry.peer, 23)
        self.assertEqual(len(entry.attrs), 3)
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        self.assertEqual(entry.attrs[2].bgp_type, 3)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertIsInstance(attr.attr_detail, BgpAttribute.BgpAttrASPath)
        path = attr.attr_detail
        self.assertEqual(len(path.pathsegs), 1)
        self.assertEqual(str(path.pathsegs[0]), "[701, 6453, 15169]")
        self.assertEqual(path.origin_as, 15169)
        self.assertEqual(mrt.as_path, path)

        assert_results = {'1.0.4.0/24': 56203,
                           '1.0.5.0/24': 56203,
                           '1.0.20.0/23': 2519,
                           '1.0.38.0/24': 24155,
                           '1.0.128.0/17': 9737,
                           '1.1.57.0/24': 132537,
                           '1.38.0.0/17': 38266,
                           '1.116.0.0/16': 131334,
                           '5.128.0.0/14': 50923,
                           '5.128.0.0/16': 31200}

        for n in range(2, 9000):
            mrt = MrtRecord.next_dump_table_record(f)
            self.assertIsInstance(mrt.table, MrtTableDump2)
            self.assertEqual(mrt.table_seq, n)
            self.assertIsNotNone(mrt.as_path)
            prefix = mrt.prefix
            origin = mrt.as_path.origin_as
            self.assertIsNotNone(origin)  # an integer or set!
            if prefix in assert_results:
                self.assertEqual(assert_results[prefix], origin, "error in origin for prefix: %s" % prefix)


    def test_mrt_table_dump_v1(self):
        """
            Tests pyasn.mrtx internal classes by converting start of an RIB TDV1 file
        """
        # todo: a file from 2008
        return

    def test_converter_full(self):
        """
            Tests pyasn.mrtx.parse_file() - converting a full RIB file
        """
        print("skipping full test (change manually)... ", file=stderr, end='')  # would be nicer to run or not via flag
        return

        converted = None
        test_limit = 11000
        with bz2.BZ2File(RIB_FULLDUMP_PATH, 'rb') as f:
            converted = parse_mrt_file(f, print_progress=True, debug_break_after=test_limit)

        util_dump_prefixes_to_textfile(converted, 'ipasntest.tmp', RIB_FULLDUMP_PATH)

        # for: 41.76.224.0/24 we get set([36994, 11845])
        # for: 184.164.242.0/24 >  seq[40191 6939 11164 10578 156 47065], set{2381} seq[47065] > so,  47065

        baseline = {}
        with open(IPASN_DB_PATH, 'rt') as f:
            for s in f:
                if s[0] == '#' or s[0] == '\n' or s[0] == ';':
                    continue
                prefix, asn = s[:-1].split()
                baseline[prefix] = int(asn)
                if test_limit and len(baseline) > test_limit:
                    break

        for prefix in converted:
            if prefix in baseline:
                # first, let's check prefixes in both. won't work if not run fully
                new = converted[prefix]
                old = baseline[prefix]
                self.assertEqual(new, old, msg="Converter returns different results: %s => %d (was: %d)" % (prefix, new, old))

        for prefix in converted:
            # a small number of prefixes will be missing in old - let's skip them manually
            self.assertIn(prefix, baseline, msg="Prefix %s extra in new converter output, wasn't before" % prefix)

        for prefix in baseline:
            # we should have all in baseline, if run fully
            self.assertIn(prefix, converted, msg="Prefix %s missing from new converter output" % prefix)

