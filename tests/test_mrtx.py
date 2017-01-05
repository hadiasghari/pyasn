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
from unittest import TestCase
from pyasn.mrtx import *
from bz2 import BZ2File
import gzip
from os import path
import logging

RIB_TD1_PARTDUMP = path.join(path.dirname(__file__), "../data/rib.20080501.0644_firstMB.bz2")
RIB_TD2_PARTDUMP = path.join(path.dirname(__file__), "../data/rib.20140523.0600_firstMB.bz2")
RIB6_TD2_PARTDUMP = path.join(path.dirname(__file__), "../data/rib6.20151101.0600_firstMB.bz2")
RIB_TD2_RECORD_FAIL_PARTDUMP = path.join(path.dirname(__file__),
                                         "../data/bview.20140112.1600_3samples.bz2")
RIB_TD1_FULLDUMP = path.join(path.dirname(__file__), "../data/rib.20080501.0644.bz2")
RIB_TD2_FULLDUMP = path.join(path.dirname(__file__), "../data/rib.20140513.0600.bz2")
RIB_TD1_WIDE_FULLDUMP = path.join(path.dirname(__file__), "../data/rib_rvwide.20040701.0000.bz2")
RIB_TD2_REPEATED_FAIL_FULLDUMP = path.join(path.dirname(__file__), "../data/rib.20170102.1400.bz2")
RIB6_TD2_FULLDUMP = path.join(path.dirname(__file__), "../data/rib6.20151101.0600.bz2")
IPASN_TD1_DB = path.join(path.dirname(__file__), "../data/ipasn_20080501_v12.dat.gz")
IPASN_TD2_DB = path.join(path.dirname(__file__), "../data/ipasn_20140513_v12.dat.gz")
TEMP_IPASNDAT = path.join(path.dirname(__file__), "ipasn_test.tmp")


class TestMrtx(TestCase):

    def test_mrt_table_dump_v2(self):
        """
            Tests pyasn.mrtx internal classes by converting start of an RIB TD2 file
        """
        f = BZ2File(RIB_TD2_PARTDUMP, 'rb')

        # first record: TDV2 (13), PEERIX (1)
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP_V2)
        self.assertEqual(mrt.sub_type, MrtRecord.T2_PEER_INDEX)
        self.assertEqual(mrt.ts, 1400824800)
        self.assertEqual(mrt.data_len, 619)
        self.assertNotEqual(mrt.detail, None)

        # second record - "0.0.0.0/0" to 16637
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP_V2)
        self.assertEqual(mrt.sub_type, MrtRecord.T2_RIB_IPV4)
        self.assertEqual(mrt.ts, 1400824800)
        self.assertEqual(mrt.data_len, 51)
        self.assertTrue(isinstance(mrt.detail, MrtTD2Record))
        self.assertEqual(mrt.detail.seq, 0)
        self.assertEqual(mrt.prefix, "0.0.0.0/0")
        self.assertEqual(mrt.detail.entry_count, 1)
        entry = mrt.detail.entries[0]
        self.assertEqual(entry.attr_len, 36)
        self.assertEqual(entry.peer, 32)
        self.assertEqual(entry.orig_ts, 1399538361)
        # self.assertEqual(len(entry.attrs), 4) -- due to optimization not reading other attributes
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.path_detail(), BgpAttribute.BgpAttrASPath))
        aspath = attr.path_detail()
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "sequence[2905, 65023, 16637]")
        self.assertEqual(aspath.get_origin_as(), 16637)

        # third record -
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertTrue(isinstance(mrt.detail, MrtTD2Record))
        self.assertEqual(mrt.data_len, 1415)
        self.assertEqual(mrt.detail.seq, 1)
        self.assertEqual(mrt.prefix, "1.0.0.0/24")
        self.assertEqual(mrt.detail.entry_count, 32)  # wow!
        entry = mrt.detail.entries[0]
        self.assertEqual(entry.attr_len, 29)
        self.assertEqual(entry.peer, 23)
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.path_detail(), BgpAttribute.BgpAttrASPath))
        aspath = attr.path_detail()
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "sequence[701, 6453, 15169]")
        self.assertEqual(aspath.get_origin_as(), 15169)

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

        for seq in range(2, 9000):
            mrt = MrtRecord.next_dump_table_record(f)
            self.assertTrue(isinstance(mrt.detail, MrtTD2Record))
            self.assertEqual(mrt.detail.seq, seq)
            # self.assertTrue(mrt.as_path is not None)
            prefix = mrt.prefix
            origin = mrt.get_first_origin_as()
            self.assertTrue(origin)  # an integer or set!
            if prefix in assert_results:
                self.assertEqual(assert_results[prefix],
                                 origin,
                                 "error in origin for prefix: %s" % prefix)

    def test_mrt_table_dump_v1(self):
        """
            Tests pyasn.mrtx internal classes by converting start of an RIB TD1 file
        """
        f = BZ2File(RIB_TD1_PARTDUMP, 'rb')

        # first record: TDV1 (10). prefix "0.0.0.0/0"
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP)
        self.assertEqual(mrt.sub_type, MrtRecord.T1_AFI_IPv4)
        self.assertEqual(mrt.ts, 1209624298)
        self.assertEqual(mrt.data_len, 42)
        self.assertTrue(isinstance(mrt.detail, MrtTD1Record))
        self.assertEqual(mrt.detail.seq, 0)
        self.assertEqual(mrt.prefix, "0.0.0.0/0")
        self.assertEqual(mrt.detail.attr_len, 20)
        self.assertEqual(mrt.detail.peer_as, 11686)
        self.assertEqual(mrt.detail.orig_ts, 1209453195)
        # self.assertEqual(len(mrt.detail.attrs), 3)  2 if optimization is on!
        self.assertEqual(mrt.detail.attrs[0].bgp_type, 1)
        self.assertEqual(mrt.detail.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = mrt.detail.attrs[1]
        self.assertEqual(attr.flags, 64)
        self.assertEqual(len(attr.data), 6)
        self.assertTrue(isinstance(attr.path_detail(), BgpAttribute.BgpAttrASPath))
        aspath = attr.path_detail()
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "sequence[11686, 3561]")
        self.assertEqual(aspath.get_origin_as(), 3561)

        # second, then third record -
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertTrue(isinstance(mrt.detail, MrtTD1Record))
        self.assertEqual(mrt.detail.seq, 1)
        self.assertEqual(mrt.prefix, "0.0.0.0/0")

        mrt = MrtRecord.next_dump_table_record(f)
        self.assertTrue(isinstance(mrt.detail, MrtTD1Record))
        self.assertEqual(mrt.detail.seq, 2)
        self.assertEqual(mrt.prefix, "3.0.0.0/8")
        self.assertEqual(mrt.detail.attr_len, 67)
        self.assertEqual(mrt.detail.peer_as, 13237)
        self.assertEqual(mrt.detail.attrs[0].bgp_type, 1)
        self.assertEqual(mrt.detail.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = mrt.detail.attrs[1]
        self.assertEqual(attr.flags, 64)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.path_detail(), BgpAttribute.BgpAttrASPath))
        aspath = attr.path_detail()
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "sequence[13237, 3320, 1239, 701, 703, 80]")
        self.assertEqual(aspath.get_origin_as(), 80)

        assert_results = {
            '3.0.0.0/8': 80,
            '4.79.181.0/24': 14780,
            '6.9.0.0/20': 668,
            '8.2.118.0/23': 13909,
            '8.3.52.0/23': 26759,
            '8.4.96.0/20': 15162,
            '8.6.48.0/21': 36492,
            '8.7.81.0/24': 25741,
            '8.7.232.0/24': 13909,
            }
        for seq in range(3, 9000):
            mrt = MrtRecord.next_dump_table_record(f)
            self.assertTrue(isinstance(mrt.detail, MrtTD1Record))
            self.assertEqual(mrt.detail.seq, seq)
            # self.assertTrue(mrt.as_path is not None)
            prefix = mrt.prefix
            origin = mrt.get_first_origin_as()
            self.assertTrue(origin)  # an integer or set!
            if prefix in assert_results:
                self.assertEqual(assert_results[prefix],
                                 origin,
                                 "error in origin for prefix: %s" % prefix)

    def test_converter_full_v2(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() - converts a full (TD2) RIB file, and compares
            results with pyasn v1.2
        """
        self.dotest_converter_full(RIB_TD2_FULLDUMP, IPASN_TD2_DB)

    def test_converter_full_v1(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() - converts a full (TD1) RIB file, and compares
            results with pyasn v1.2
        """
        self.dotest_converter_full(RIB_TD1_FULLDUMP, IPASN_TD1_DB)

    def dotest_converter_full(self, full_ribdump_path, ipasn_db_path=None):
        # internal method called by both test_converter_full_v1 & test_converter_full_v2
        if not path.isfile(full_ribdump_path):
            print("SKIPPING - full dump doesn't exist.", file=stderr, end='')
            return

        print("starting conversion of", full_ribdump_path.split('/')[-1], file=stderr)
        converted = parse_mrt_file(full_ribdump_path, print_progress=True)
        v6 = sum(1 for x in converted if ':' in x)
        print("  Converted %d IPV4 + %d IPV6 prefixes." % (len(converted) - v6, v6), file=stderr)

        if not ipasn_db_path:
            return  # nothing more to compare!

        # test of write-output
        dump_prefixes_to_text_file(converted,
                                   TEMP_IPASNDAT,
                                   full_ribdump_path,
                                   debug_write_sets=True)

        # tests of comparing with v 1.2 (existing conversion): load it, then compare
        # an alternative option is to run a linux DIFF comppand between TMEP_IPASNDAT & IPASN_DB
        ipasndat_v12 = {}
        f = gzip.open(ipasn_db_path, "rt") if ipasn_db_path.endswith(".gz") else \
            open(ipasn_db_path, "rt")
        for s in f:
            if s[0] == '#' or s[0] == '\n' or s[0] == ';':
                continue
            prefix, asn = s[:-1].split()
            ipasndat_v12[prefix] = int(asn)
        f.close()  # Py2.6 doesn't support 'with' for gzip files

        print("Comparing %d new vs %d old conversions" % (len(converted), len(ipasndat_v12)),
              file=stderr)

        bogus_count = 0
        for prefix in converted:
            if prefix in ipasndat_v12:
                # first, let's check prefixes in both. won't work if not run fully
                origin = converted[prefix]
                old = ipasndat_v12[prefix]
                # changes 2014/11/02, now we don't return bogus origin ASNs
                if not is_asn_bogus(old):
                    msg = "Converter results differ: %s => %d (was %d)" % (prefix, origin, old)
                    self.assertEqual(origin, old, msg=msg)
                else:
                    bogus_count += 1
                    msg = "Converter returned bogus route: %s => %d" % (prefix, origin)
                    self.assertTrue(not is_asn_bogus(origin), msg=msg)

        self.assertTrue(bogus_count < 214,
                        msg="Many unexplained updated bogus prefixes: %d" % bogus_count)
        # 98 for 20140523; 213 for 20080501
        print("Updated bogus prefixes in new converter: %d" % bogus_count, file=stderr)

        skipped_count = 0
        for prefix in converted:
            # check if prefixes in converted are in baseline.
            # most should be -- (a few, 129 out of 513k, were returned NONE in pyasn 1.2)
            if prefix not in ipasndat_v12:
                skipped_count += 1
                origin = converted[prefix]
                if prefix in ("162.212.40.0/24",
                              "192.88.192.0/24",
                              "199.193.100.0/22",
                              "207.35.39.0/24"):
                    # These prefix are new & checked to be ok in 2014/05/13.
                    # They aren't "set" because the set items are all bogus, so previous
                    # segment/sequence was returned
                    continue
                self.assertTrue(isinstance(origin, set),
                                msg="Unexplained non-set prefix %s in output" % prefix)

        self.assertTrue(skipped_count < 132,
                        msg="Many unexplained new prefixes: %d" % skipped_count)
        # 131 for 20140523; 52 for 20080501
        print("Prefixes in new converter (skipped before): %d" % skipped_count, file=stderr)

        # we should have all in baseline, if run fully
        for prefix in ipasndat_v12:
            self.assertTrue(prefix in converted,
                            msg="Prefix %s missing from new converter output" % prefix)

    def test_mrt6_table_dump_v2(self):
        """
            Tests pyasn.mrtx internal classes by converting start of an RIB6 TD2 file (IPv6)
        """
        f = BZ2File(RIB6_TD2_PARTDUMP, 'rb')

        # first record
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP_V2)
        self.assertEqual(mrt.sub_type, MrtRecord.T2_PEER_INDEX)
        self.assertEqual(mrt.ts, 1446357600)
        self.assertEqual(mrt.data_len, 733)
        self.assertNotEqual(mrt.detail, None)

        # second record
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertEqual(mrt.type, MrtRecord.TYPE_TABLE_DUMP_V2)
        self.assertEqual(mrt.sub_type, MrtRecord.T2_RIB_IPV6)
        self.assertEqual(mrt.ts, 1446357600)
        self.assertEqual(mrt.data_len, 1741)
        self.assertTrue(isinstance(mrt.detail, MrtTD2Record))
        self.assertEqual(mrt.detail.seq, 0)
        self.assertEqual(mrt.prefix, "2001::/32")
        self.assertEqual(mrt.detail.entry_count, 24)
        entry = mrt.detail.entries[0]
        self.assertEqual(entry.attr_len, 85)
        self.assertEqual(entry.peer, 10)
        self.assertEqual(entry.orig_ts, 1446348241)
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.path_detail(), BgpAttribute.BgpAttrASPath))
        aspath = attr.path_detail()
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "sequence[3257, 1103, 1101]")
        # Note: can't figure out if 1101 or this path sequence is correct
        self.assertEqual(aspath.get_origin_as(), 1101)

        # third record -
        mrt = MrtRecord.next_dump_table_record(f)
        self.assertTrue(isinstance(mrt.detail, MrtTD2Record))
        self.assertEqual(mrt.data_len, 1724)
        self.assertEqual(mrt.detail.seq, 1)
        self.assertEqual(mrt.prefix, "2001:4:112::/48")
        self.assertEqual(mrt.detail.entry_count, 23)
        entry = mrt.detail.entries[0]
        self.assertEqual(entry.attr_len, 87)
        self.assertEqual(entry.peer, 10)
        self.assertEqual(entry.attrs[0].bgp_type, 1)
        self.assertEqual(entry.attrs[1].bgp_type, BgpAttribute.ATTR_AS_PATH)
        attr = entry.attrs[1]
        self.assertEqual(attr.flags, 80)
        self.assertEqual(len(attr.data), 14)
        self.assertTrue(isinstance(attr.path_detail(), BgpAttribute.BgpAttrASPath))
        aspath = attr.path_detail()
        self.assertEqual(len(aspath.pathsegs), 1)
        self.assertEqual(str(aspath.pathsegs[0]), "sequence[3257, 1103, 112]")
        self.assertEqual(aspath.get_origin_as(), 112)

        # follow list chosen from the file; randomly did WHOIS lookups on prefixes; correct
        assert_results = {"2001:504:2e::/48": 10578,
                          "2001:57a:e030::/45": 22773,
                          "2001:590:1800::/38": 4436,
                          "2001:67c:368::/48": 12509,
                          "2001:67c:14d8::/48": 61413,
                          "2001:67c:22f4::/48": 200490,
                          "2001:67c:2c90::/48": 60092,
                          "2001:978:1801::/48": 174,
                          "2001:dc5:0:55::/64": 9700,
                          "2001:df2:f000::/48": 55319,
                          "2001:12c4::/32": 28262,
                          "2001:1838:5000::/40": 23352,
                          "2001:1a88::/32": 15600,
                          "2001:4478:1900::/40": 4802,  # part of a /30? IINET-SIXNET. AS: IINET.
                          "2001:4888:4:fe00::/64": 22394,
                          "2001:49f0:a015::/48": 174,
                          "2001:b032:1b::/48": 3462,
                          "2400:bc00:1800::/48": 10115,
                          "2401:4800::/32": 38457,
                          "2402:a00:111::/48": 45916,
                          "2402:db00::/32": 132142,
                          "2403:bc00:1::/48": 45668,
                          "2404:8000:9::/48": 17451,
                          "2405:1e00:8::/48": 17771,
                          "2406:3000:11:1026::/64": 4657,  # part of /48. StarHub-Ltd. AS: StarHub
                          "2406:5600:6a::/48": 131222,
                          "2407:3100::/48": 10118,
                          "2600:1:a154::/46": 3651,
                          "2600:380:5c00::/38": 20057,
                          "2600:1006:8020::/44": 22394,
                          "2600:1404:23::/48": 20940,
                          "2600:3004::/32": 13649,
                          "2600:8801:2900::/41": 22773,
                          "2604:200::/32": 33132,
                          "2604:a680:2::/48": 55079,
                          "2605:2a80::/32": 62489,
                          "2605:dc80::/48": 31985,
                          "2606:2800:4a6c::/48": 15133,
                          "2606:b400:8018::/48": 792,
                          "2607:cf03::/34": 40583,
                          "2607:f2c8::/32": 13730,
                          "2607:f748::/32": 32613,
                          "2607:fcc0::/32": 36483,
                          "2610:f8::/32": 26398,
                          "2620:3a:400d::/48": 36711,
                          "2620:100:6000::/44": 19679,
                          "2620:10a:9047::/48": 11133,
                          "2620:11b:400e::/47": 47870,
                          "2800:68:15::/48": 52343,
                          "2800:e00::/24": 27665,  # PREFIX: ROM16-COLUMBUSTRINIDAD.COM. AS: same
                          "2803:a200:4::/48": 263240,
                          "2804:14c:bf40::/42": 28573,
                          "2804:214:8241::/48": 26615,
                          "2804:7f5:8000::/33": 18881,
                          "2804:1270:a2::/48": 262851,
                          "2804:2554::/32": 264274,
                          "2a00:10ef::/32": 5413,
                          "2a00:18c0::/32": 8402,
                          "2a00:4140::/32": 34766,
                          "2a00:7ac0::/32": 196742,
                          "2a00:aa80::/32": 51474,
                          "2a00:e8c0::/32": 34797,
                          "2a01:528::/32": 6775,  # correct in whois
                          "2a01:6c60:1000::/36": 62217,
                          "2a01:8840:c0::/48": 12041,
                          "2a01:c9c0:a5::/48": 8891,
                          "2a02:690::/32": 41960,
                          "2a02:fb0::/32": 5503,
                          "2a02:2698:1800::/38": 51604,
                          "2a02:2928::/32": 39288,
                          "2a02:7820::/32": 201873,
                          "2a02:e980:43::/48": 19551,
                          "2a03:2c80::/32": 31084,
                          "2a03:7380:1f80::/42": 13188,  # correct in WHOIS
                          "2a03:cd00::/32": 1668,
                          "2a04:4940::/29": 60278,
                          "2a04:e4c0:14::/48": 36692,
                          "2a05:d880:1::/48": 43066,
                          "2a06:9800::/29": 6908,
                          }

        for seq in range(2, 2000):
            mrt = MrtRecord.next_dump_table_record(f)
            self.assertTrue(isinstance(mrt.detail, MrtTD2Record))
            self.assertEqual(mrt.detail.seq, seq)
            # self.assertTrue(mrt.as_path is not None)
            prefix = mrt.prefix
            origin = mrt.get_first_origin_as()
            self.assertTrue(origin)  # an integer or set!
            if prefix in assert_results:
                self.assertEqual(assert_results[prefix],
                                 origin,
                                 "error in origin for prefix: %s" % prefix)

    def test_converter_full_v2_ip6(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() - converts a full (TD2) RIB file with IPv6;
            discards output
        """
        self.dotest_converter_full(RIB6_TD2_FULLDUMP)

    def test_skip_all_line_on_single_error_with_boolean_false(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() with skip_record_on_error set to default(False);
        """
        self.assertRaises(IndexError, parse_mrt_file, RIB_TD2_RECORD_FAIL_PARTDUMP)

    def test_read_all_line_on_single_error_with_boolean_true(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() with skip_record_on_error set to True
        """
        res = parse_mrt_file(RIB_TD2_RECORD_FAIL_PARTDUMP, skip_record_on_error=True)
        self.assertEqual(len(res), 2)

    def test_parsing_repeated_prefixes_tabledump(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() with repeated prefixes causing errros (bug #39)
        """
        self.dotest_converter_full(RIB_TD2_REPEATED_FAIL_FULLDUMP)

    def test_parsing_rviews_wide_td1(self):
        """
            Tests pyasn.mrtx.parse_mrt_file() with routeviews WIDE archive TD1 (bug #42)
        """
        self.dotest_converter_full(RIB_TD1_WIDE_FULLDUMP)
