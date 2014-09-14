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

# This file parses the Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format dumps

# Parts of this code are copied/based on the dpkt project, with their respective copyright
# (see: https://code.google.com/p/dpkt/)

from __future__ import print_function, division
from socket import inet_ntoa
from struct import unpack, pack
from time import time, asctime

"""pyasn.mrtx: module to parse MRT/RIB BGP table dumps (in order to convert them IPASN database

   pyasn.mrtx.parse_file(file_descriptor):
    
   pyasn.mrtx.MRT_* classes: internally used to hold and parse the MRT dumps.
"""

# Note: currently it has only IPv4 support. For IPv6 support, changes are needed, partially marked in code.


def parse_mrt_file(file, print_progress=False, debug_break_after=None):
    """parse_file(file, print_progress=False):
Parses an MRT/RIB dump file.\n
    in: opened dump file to use (file-object)
    out: { "NETWORK/MASK" : ASN | set([Originating ASNs]) }
\nBoth version 1 & 2 table dumps are supported, as well as 32bit ASNs.
The originating ASN is usually one; however, for some prefixes (explained in the class), it's unclear amoung a few.
"""  
    results = {}
    n, stime = 0, time()
    while True:
        mrt = MrtRecord.next_dump_table_record(file)
        if not mrt:
            # EOF
            break
        if not mrt.table:
            # skip entry
            if print_progress:
                print('parse_file(): starting  parse for %s' % mrt)
            continue

        origin = mrt.as_path.origin_as
        # important change from pyasn_converter 1.2"
        #   in 1.2, we ignored origins of as_paths ending in as_set (with one AS - quite common - or multiple )
        #   as well as origins of as_paths with more than three segments (very few)
        #   this was a silly bug as these prefixes would not be saved (impact: 129 of 513000 prefixes for 2014-05-23)

        if mrt.prefix not in results:
            results[mrt.prefix] = origin
        else:
            assert mrt.type == mrt.TYPE_TABLE_DUMP
            # in type2, no prefix appears twice. (probably because we use *only entry 0 of records* -- is this ok?)
            # in type1, they do, "but we are only interested in getting the first match" (quote from asn v1.2)
            #           what happens if not equal? perhaps even one ASN-set, one a specific ASN...
            if results[mrt.prefix] != origin:
                pass

        n += 1
        if debug_break_after and n > debug_break_after:
            break
        if print_progress and n % 10000 == 0:
            print('record %d @%.fs' % (n, time() - stime))
    #
    if '0.0.0.0/0' in results:
        del results['0.0.0.0/0']  # remove default route - can be parameter
    return results


def util_dump_prefixes_to_textfile(ipasn_dat, out_file_name, orig_mrt_name):
    fw = open(out_file_name, 'wt', encoding='ASCII')  # todo: test 'encoding' python 2
    fw.write('; IP-ASN32-DAT file\n; Original file : %s\n' % orig_mrt_name)
    fw.write('; Converted on  : %s\n; Prefixes      : %s\n; \n' % (asctime(), len(ipasn_dat)))
    for prefix, asn in sorted(ipasn_dat.items()):
        fw.write('%s\t%d\n' % (prefix, asn))
    fw.close()

    
#####################################################################
# MRT headers, tables, and attributes sections
# MRT spec at: http://tools.ietf.org/html/rfc6396)

# performance notes:
#  -this code isn't super fast, but that's OK because it's run once to convert/parse the MRT files
#  - it can be sped up perhaps by replacing some unpacks with ord(), etc, or moving to C
#  - it's not a full MRT parser;  we ignore types/attributes we don't need...

class MrtRecord:
    """Class for generic MRT Records. Implments common header, as well as methods for specific types"""

    # We are interested in MRT-record types Table_Dump & Table_Dump_V2, and among them in some sub-types
    TYPE_TABLE_DUMP = 12
    TYPE_TABLE_DUMP_V2 = 13
    T1_AFI_IPv4 = 1
    T2_PEER_INDEX_TABLE = 1
    T2_RIB_IPV4_UNICAST = 2

    # For IPv6, these types are needed
    # T1_AFI_IPv6 = 2
    # T2_RIB_IPV6_UNICAST = 4

    def __init__(self, header):
        self.ts, self.type, self.sub_type, self.data_len = unpack('>IHHI', header)
        self.table = None

    @staticmethod
    def next_dump_table_record(f):
        header_len = 12
        buf = f.read(header_len)  # read table-header
        if not buf:  # EOF
            return None
        assert len(buf) == header_len
        mrt = MrtRecord(buf)
        buf = f.read(mrt.data_len)  # read table-data
        assert len(buf) == mrt.data_len
        if mrt.type == MrtRecord.TYPE_TABLE_DUMP:
            assert mrt.sub_type == MrtRecord.T1_AFI_IPv4  # only allow this
            mrt.table = MrtTableDump1(buf, mrt.sub_type)
        elif mrt.type == MrtRecord.TYPE_TABLE_DUMP_V2:
            assert mrt.sub_type in (MrtRecord.T2_PEER_INDEX_TABLE, MrtRecord.T2_RIB_IPV4_UNICAST)  # only allow these
            # among them, T2_PEER_INDEX_TABLE provides BGP ID of the collector, and list of peers; we don't use it
            if mrt.sub_type == MrtRecord.T2_RIB_IPV4_UNICAST:
                mrt.table = MrtTableDump2(buf, mrt.sub_type)
        else:
            raise Exception("MrtTableHeader received an unknown MRT table dump TYPE <%d>!" % mrt.type)
        return mrt

    def __str__(self):
        return 'MrtTable {ts:%d, type:%d, sub-type:%d, data-len:%d, seq:%s, prefix:%s}' \
               % (self.ts, self.type, self.sub_type, self.data_len, self.table_seq, self.prefix)

    @property
    def prefix(self):
        return self.table.s_prefix if self.table else None  # for IPV4, it's a CIDR/MASK string

    @property
    def table_seq(self):
        return self.table.seq if self.table else None

    @property
    def as_path(self):
        path = None
        # For MRTDUMPv2 we only use entry 0 attributes. is this OK? (DumpV1 only has single entry)
        attrs = self.table.attrs if self.type == MrtRecord.TYPE_TABLE_DUMP else self.table.entries[0].attrs
        for a in attrs:
            if a.bgp_type == BgpAttribute.ATTR_AS_PATH:
                assert not path  # we have only one as-path attribute in each entry
                path = a.attr_detail
        assert path
        return path


class MrtTableDump1:
    """MrtTableDump1: class to hold and parse MRT Table_Dumps records"""

    def __init__(self, buf, sub_type1):
        assert sub_type1 == MrtRecord.T1_AFI_IPv4  # for IPv6: prefix-size (16B vs 4B) & way handled is different
        self.view, self.seq, prefix, mask, self.status, self.orig_ts, self.peer_ip, self.peer_as, self.attr_len\
            = unpack('>HHIBBIIHH', buf[:22])

        s_prefix = '%d.%d.%d.%d' % (prefix >> 24 & 0xff, prefix >> 16 & 0xff, prefix >> 8 & 0xff, prefix & 0xff)
        assert s_prefix == inet_ntoa(pack('>I', prefix))  # temp test
        self.s_prefix = s_prefix + "/%d" % mask

        assert self.view == 0  # view is normally 0; its intended for when an implementation has multiple RIB views
        # The BGP Attribute field contains the BGP attribute information for the RIB entry.

        buf = buf[22:]
        self.attrs = []
        j = self.attr_len
        while j > 0:
            a = BgpAttribute(buf, is32=False)
            self.attrs.append(a)
            buf = buf[len(a):]
            j -= len(a)
        assert not j and not buf  # make sure all data is used


    def __str__(self):
        return 'MrtTableDump1 {seq:%d, prefix:%s + sole entry [attr-len:%d, peer:%d, orig-ts:%d]}' % \
            (self.seq, self.s_prefix, self.attr_len, self.peer_as, self.orig_ts)


class MrtTableDump2:
    """MrtTableDump2: class to hold and parse MRT records form Table_Dumps_V2"""

    # Main difference was support of 4-byte ASNs, and support for BGP multiprotocol extensions.
    # Also, they permit a single MRT record to encode multiple RIB table entries for a single prefix.

    def __init__(self, buf, sub_type2):
        self.seq = unpack('>I', buf[0:4])[0]
        mask = buf[4]
        octets = (mask + 7) // 8
        assert sub_type2 == MrtRecord.T2_RIB_IPV4_UNICAST  # only IPv4 support for now. For IPv6, parts below need change
        assert 0 <= octets <= 4  # e.g., more octets for ipv6
        s = ".".join([str(b) for b in buf[5: 5 + octets]])  # TODO: for py2 one needs STR(ORD(b)) I think. figure this
        s_prefix = {0: '0.0.0.0', 1: s + '.0.0.0', 2: s + '.0.0', 3: s + '.0', 4: s}[octets]

       # todo: do double check: changed this to // for py3 compatibility on 2014-09-13, and changes below
        if octets == 0:  tmpx, tmps = 5, '0.0.0.0'
        elif octets == 1:  tmpx, tmps = 6, '%d.0.0.0' % buf[5]  # for python2 one needs ord
        elif octets == 2: tmpx, tmps = 7, '%d.%d.0.0' % tuple(buf[5:7])
        elif octets == 3:  tmpx, tmps = 8, '%d.%d.%d.0' % tuple(buf[5:8])
        else: tmpx, tmps = 9, '%d.%d.%d.%d' % tuple(buf[5:9])
        assert tmps == s_prefix

        self.s_prefix = s_prefix + "/%d" % mask

        entry_count = unpack('>H', buf[5 + octets:7 + octets])[0]
        buf = buf[7 + octets:]
        self.entries = []
        for i in range(entry_count):
            e = self.T2RibEntry(buf)
            self.entries.append(e)
            buf = buf[len(e):]
        assert not buf  # assert fully parsed

    def __str__(self):
        return 'MrtTableDump2 {seq:%d, prefix:%s, entries:%d}' % (self.seq, self.s_prefix, len(self.entries))

    class T2RibEntry:
        def __init__(self, buf):
            self.peer, self.orig_ts, self.attr_len = unpack('>HIH', buf[:8])
            self._data = buf[8: 8 + self.attr_len]
            self._attrs = []

        @property
        def attrs(self):
            if not self._attrs:  # parse an entry's attrs on demand for performance
                data = self._data
                j = self.attr_len
                while j > 0:
                    attr = BgpAttribute(data, is32=True)
                    data = data[len(attr):]
                    j -= len(attr)
                    self._attrs.append(attr)
                assert not j and not data  # make sure all data is used
            return self._attrs

        def __len__(self):
            return 8 + self.attr_len

        def __str__(self):
            return 'T2RibEntry {attr_len: %d, peer: %d, orig_ts: %d}' % (self.attr_len, self.peer, self.orig_ts)


class BgpAttribute:
    # BGP attributes are defined here:  http://tools.ietf.org/html/rfc4271  (Section 5)

    # They are part of BGP UPDATE messages. We are interested in the AS_PATH attribute
    # Stats on attribute in one TableDumpV2 file:
    #   1/ORIGIN 24% = generated by the speaker that originates the associated routing information
    #                  exists, but data is zero
    #   2/AS_PATH 24% = identifies the AS through which routing info carried in this message has passed
    #                   we get the advertised paths and origin/owning AS from here
    #   3/NEXT_HOP 24% = IP address of router that's next hop to the destinations listed
    #   4/MULTI_EXIT_DISC 10% = optional attribute to discriminate among multiple exit or entry points
    #   5/ATOMIC_AGGREGATE 1.5% = discretionary attribute
    #   6/AGGREGATOR 2.5% =  optional transitive attribute,
    #   7/COMMUNITIES 14% ?  (and talk of LOCAL_PREF?)
    ATTR_AS_PATH = 2

    def _has_ext_len(self):
        ext_len = (self.flags >> 4) & 0x1
        return ext_len

    def __init__(self, buf, is32):
        self.bgp_type = buf[1]
        self.flags = buf[0]
        if self._has_ext_len():
            _len = unpack('>H', buf[2:4])[0]
            self.data = buf[4:4 + _len]
        else:
            _len =  buf[2]
            self.data = buf[3:3 + _len]
        if self.bgp_type == self.ATTR_AS_PATH:
            self.attr_detail = self.BgpAttrASPath(self.data, is32)
    
    def __len__(self):
        return 2 + (2 if self._has_ext_len() else 1) + len(self.data)

    def __str__(self):
        return 'BGPAttribute {type:%d, flags:%d, len(data):%d}' % (self.bgp_type, self.flags, len(self.data))

    class BgpAttrASPath:
        # An AS_PATH has routing path information represented as ordered AS_SEQUENCEs and unordered AS_SETs.

        def __init__(self, buf, is32):
            self.pathsegs = []
            while buf:
                seg = self.BgpPathSegment(buf, is32)
                buf = buf[len(seg):]
                self.pathsegs.append(seg)

        def __str__(self):
            s = " "
            for path in self.pathsegs:
                s += "set" if path.seg_type == self.BgpPathSegment.AS_SET else "seg"
                s += "(%d)<" % len(path)
            return 'BgpAttrASPath {pathsegs: ' + s[:-1] + '}'

        @property
        def origin_as(self):
            """Returns the originating AS for this prefix - an integer if clear, a set of integers not fully unclear"""

            # To identify the originating AS for a prefix, we need to understand how the path-segments work

            # RFC 4271 on how AS_PATH is created
            # - when a BGP speaker advertises route to an internal peer, it shall not modify the AS_PATH
            # - when a BGP speaker advertises the route to an external peer, it updates AS_PATH attribute as follows:
            #   - if first path segment of AS_PATH is AS_SEQUENCE, the local system prepends its own ASN (leftmost)
            #     if more than 255 ASes already, prepends a new AS_SEQUENCE segment
            #   - if first path segment is AS_SET, its prepends a new AS_SEQUENCE segment to the AS_PATH,
            #     including its own AS number in that segment.
            #   - if AS_PATH is empty, it creates a AS_SEQUENCE segment, places its own AS into it and it into AS_PATH
            # - When a BGP speaker originates a route:
            #   - the speaker includes its own ASN in a path segment of type AS_SEQUENCE, in the AS_PATH attribute of
            #     UPDATE messages sent to external peers. (i.e., its ASN will be sole entry)
            #   - the originating speaker includes an empty AS_PATH attribute in UPDATE messages sent to internal peers.
            #
            # So none of the above uses AS_SET; AS_SET is used in aggregate messages.
            # - When a speaker aggregates several routes for advertisement to a particular peer, the AS_PATH of
            #   the aggregated route normally includes an AS_SET from the set of ASes the was aggregate was formed.
            # - Caveat: AS_SETs, used in route aggregation to reduce the size of the AS_PATH info by listing each ASN
            #   only once (regardless of times it appeared in multiple AS_PATHs), can cause some inaccuracies.
            #   The destinations listed can be reached through paths that traverse at least some constituent ASes.
            #   AS_SETs are sufficient to avoid routing loops; however, they may prune feasible paths. In practice,
            #   this is not a problem because once an IP packet arrives at the edge of a group of ASes, the BGP speaker
            #   is likely to have more detailed path information.

            # So basically:
            #  i- go to the last path segment, among the many.
            #  ii- if it's a sequence, return the last AS; if it's a set, return all ASes; callee can choose any

            origin = None
            #  assert: sequence & sets can interleave; but always at least one sequence will be before a set!
            assert self.pathsegs[0].seg_type == self.BgpPathSegment.AS_SEQUENCE
            last_seg = self.pathsegs[-1]
            if last_seg.seg_type == self.BgpPathSegment.AS_SEQUENCE:
                origin = int(last_seg.path[-1])
            elif last_seg.seg_type == self.BgpPathSegment.AS_SET:
                origin = set(last_seg.path) if len(last_seg.path) > 1 else int(last_seg.path[-1])
            if len(self.pathsegs) > 2:
                pass  # had a bug before, when > 2 path segments we returned nothing. not sure how often it happened
            return origin

        class BgpPathSegment:
            AS_SET = 1  # AS_SET: unordered set of ASes a route in the UPDATE message has traversed
            AS_SEQUENCE = 2  # AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed
            #  stats on 100,000: {1: 1196, 2: 3677845}.

            def __init__(self, data, is32):
                self.seg_type, cnt = unpack('>BB', data[:2])
                data = data[2:]
                assert self.seg_type in (self.AS_SET, self.AS_SEQUENCE)  # also 3?
                self.path = []
                self.as_len = 4 if is32 else 2
                for i in range(cnt):
                    asn = unpack('>I' if is32 else '>H', data[:self.as_len])[0]
                    assert asn > 0
                    data = data[self.as_len:]
                    self.path.append(asn)

            def __len__(self):
                return 2 + self.as_len * len(self.path)

            def __str__(self):
                # for path-sequences: [as1, as2, as3], for path-sets: set([as1, as2, as3])
                assert self.seg_type in (self.AS_SET, self.AS_SEQUENCE)
                s = '' if self.seg_type == self.AS_SEQUENCE else 'set('
                s += str(self.path)
                s += '' if self.seg_type == self.AS_SEQUENCE else ')'
                return s
