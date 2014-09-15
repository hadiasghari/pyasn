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

from __future__ import print_function, division
from unittest import TestCase
from pyasn.mrtx import *
import bz2
from os import path
import logging

IPASN_DB_PATH = path.join(path.dirname(__file__), "../data/ipasn_20140513.dat")
RIB_FULLDUMP_PATH = path.join(path.dirname(__file__), "../data/rib.20140513.0600.bz2")
RIB_PARTDUMP_PATH = path.join(path.dirname(__file__), "../data/rib.20140523.0600_firstMB.bz2")
TMP_IPASN_PATH = path.join(path.dirname(__file__), "ipasn_test_dat.tmp")
# logger = logging.getLogger()


class ConvertMRTFile(TestCase):
    def test_mrt_table_dump_v2(self):
        """
            Tests pyasn.mrtx internal classes by converting start of an RIB TDV2 file
        """
        f = bz2.BZ2File(RIB_PARTDUMP_PATH, 'rb')

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
        self.assertTrue(isinstance(mrt.table, MrtTableDump2))
        self.assertEqual(mrt.table_seq, 0)
        self.assertEqual(mrt.prefix, "0.0.0.0/0")
        self.assertEqual(mrt.table.entry_count, 1)
        entry = mrt.table.entries[0]
        self.assertEqual(entry.attr_len, 36)
        self.assertEqual(entry.peer, 32)
        self.assertEqual(entry.orig_ts, 1399538361)
        #self.assertEqual(len(entry.attrs), 4) -- due to optimization i'm not reading rest of attributes
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.attr_detail, BgpAttribute.BgpAttrASPath))
        aspath = attr.attr_detail
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "[2905, 65023, 16637]")
        self.assertEqual(aspath.origin_as, 16637)
        self.assertEqual(mrt.as_path, aspath)

        # third record -
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertTrue(isinstance(mrt.table, MrtTableDump2))
        self.assertEqual(mrt.data_len, 1415)
        self.assertEqual(mrt.table_seq, 1)
        self.assertEqual(mrt.prefix, "1.0.0.0/24")
        self.assertEqual(mrt.table.entry_count, 32)  # wow!
        entry = mrt.table.entries[0]
        self.assertEqual(entry.attr_len, 29)
        self.assertEqual(entry.peer, 23)
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.attr_detail, BgpAttribute.BgpAttrASPath))
        aspath = attr.attr_detail
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "[701, 6453, 15169]")
        self.assertEqual(aspath.origin_as, 15169)
        self.assertEqual(mrt.as_path, aspath)

        assert_results = {'1.0.4.0/24': 56203,
                          '1.0.5.0/24': 56203,
                          '1.0.20.0/23': 2519,
                          '1.0.38.0/24': 24155,
                          '1.0.128.0/17': 9737,
                          '1.1.57.0/24': 132537,
                          '1.38.0.0/17': set([38266]),
                          '1.116.0.0/16': 131334,
                          '5.128.0.0/14': set([50923]),
                          '5.128.0.0/16': 31200}

        for n in range(2, 9000):
            mrt = MrtRecord.next_dump_table_record(f)
            self.assertTrue(isinstance(mrt.table, MrtTableDump2))
            self.assertEqual(mrt.table_seq, n)
            self.assertTrue(mrt.as_path is not None)
            prefix = mrt.prefix
            origin = mrt.as_path.origin_as
            self.assertTrue(origin)  # an integer or set!
            if prefix in assert_results:
                self.assertEqual(assert_results[prefix], origin, "error in origin for prefix: %s" % prefix)


    # todo: same as above, but with an MRT file from 2008
    # def test_mrt_table_dump_v1(self):
    #    """Tests pyasn.mrtx internal classes by converting start of an RIB TDV1 file"""

    def test_converter_full(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() - converts a full (TD2) RIB file, and compares results with pyasn v1.2
        """
        if not path.isfile(RIB_FULLDUMP_PATH):
            print("skip test, full rib dump doesn't exist... ", file=stderr, end='')
            return

        f = bz2.BZ2File(RIB_FULLDUMP_PATH, 'rb')
        converted = parse_mrt_file(f, print_progress=True, debug_break_after=None)
        f.close()

        # test of write-output
        dump_prefixes_to_text_file(converted, TMP_IPASN_PATH, RIB_FULLDUMP_PATH, debug_write_sets=True)

        # tests of comparing with v 1.2: load it, then compare
        # an alternative option is to run a linux DIFF comppand between TMP_IPASN_PATH & IPASN_DB_PATH
        ipasndat_v12 = {}
        with open(IPASN_DB_PATH, 'rt') as f:
            for s in f:
                if s[0] == '#' or s[0] == '\n' or s[0] == ';':
                    continue
                prefix, asn = s[:-1].split()
                ipasndat_v12[prefix] = int(asn)

        for prefix in converted:
            if prefix in ipasndat_v12:
                # first, let's check prefixes in both. won't work if not run fully
                origin = converted[prefix]
                old = ipasndat_v12[prefix]
                self.assertEqual(origin, old, msg="Converter results differ: %s => %d (was %d)" % (prefix, origin, old))

        skipped_count = 0
        for prefix in converted:
            # check if prefixes in converted are in baseline.
            # most should be, a few (129 out of 513k) were returned NONE in pyasn 1.2 output used here as comparison
            if prefix not in ipasndat_v12:
                skipped_count += 1
                origin = converted[prefix]
                self.assertTrue(isinstance(origin, set), msg="Unexplained extra prefix %s in output" % prefix)

        self.assertTrue(skipped_count < 132, msg="Many unexplained prefixes in new converter: %d" % skipped_count)
        print("Prefixes in new converter (skipped before): %d" % skipped_count, file=stderr)

        # we should have all in baseline, if run fully
        for prefix in ipasndat_v12:
            self.assertTrue(prefix in converted, msg="Prefix %s missing from new converter output" % prefix)
