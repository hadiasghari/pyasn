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

"""pyasn.mrtx
Module to parse MRT/RIB BGP table dumps (in order to create the IPASN database).

Functions:
  parse_mrt_file()  -- main function
  util_dump_prefixes_to_textfile()

Other objects:
   MRT* and pyasn.mrtx.BGP* classes: internally used to hold and parse the MRT dumps.
"""

from __future__ import print_function, division
from socket import inet_ntoa, inet_aton, inet_ntop, AF_INET, AF_INET6
from struct import unpack, pack
from time import time, asctime
from sys import stderr, version_info
try:
    from collections import OrderedDict
except:
    # python 2.6 support - needs the ordereddict module
    from ordereddict import OrderedDict

IS_PYTHON2 = (version_info[0] == 2)


def parse_mrt_file(mrt_file, print_progress=False, debug_break_after=None, skip_record_on_error=False):
    """parse_file(file, print_progress=False):
Parses an MRT/RIB dump file.\n
    in: opened dump file to use (file-object)
    out: { "NETWORK/MASK" : ASN | set([Originating ASNs]) }
\n
The originating ASN is usually one; however, for some prefixes (explained in the module), it's unclear, among a few.
\n
Both version 1 & 2 TABLE_DUMPS are supported, as well as 32bit ASNs. IPv6 implemented for TD2.
"""
    results = OrderedDict()
    n, stime = 0, time()
    while True:
        mrt = MrtRecord.next_dump_table_record(mrt_file)
        if not mrt:
            # EOF
            break
        if not mrt.table:
            # skip entry
            if print_progress:
                print('parse_mrt_file(): starting  parse for %s' % mrt)
            continue

        # important change from pyasn_converter 1.2"
        #   in 1.2, we ignored origins of as_paths ending in as_set (with one AS - quite common - or multiple )
        #   as well as origins of as_paths with more than three segments (very few)
        #   this was a silly bug, andthese prefixes (129 in a total of 513000 prefixes for 2014-05-23) weren't saved

        if mrt.prefix not in results:
            try:
                #if mrt.prefix in ("162.212.40.0/24", "192.88.192.0/24", "199.193.100.0/22", "207.35.39.0/24"):
                #    print("  DEBUG %s for %s" % (mrt.as_path, mrt.prefix), file=stderr)
                origin = mrt.as_path.origin_as
                results[mrt.prefix] = origin
	    except IndexError:
                if skip_record_on_error:
                    print("  IndexError parsing prefix '%s' ..Skipping it" % (mrt.prefix), file=stderr)  # to aid debugging
                    continue
                else:
                    raise
            except:
                # Log the error and raise it again
                print("  Error parsing prefix '%s'" % (mrt.prefix), file=stderr)  # to aid debugging
                raise
        else:
            assert mrt.type == mrt.TYPE_TABLE_DUMP
            # in TD2, no prefix appears twice. (probably because we use *only entry 0 of records* -- is this ok?)
            # in TD1, they do, "but we are only interested in getting the first match" (quote from asn v1.2)
            #          for one TD1 dump checked: all duplicate prefixes had same origin (we don't assert all for speed)

        n += 1
        if debug_break_after and n > debug_break_after:
            break
        if print_progress and n % (100000 if mrt.type == mrt.TYPE_TABLE_DUMP_V2 else 500000) == 0:
            print('  MRT record %d @%.fs' % (n, time() - stime), file=stderr)
    #
    if '0.0.0.0/0' in results:
        del results['0.0.0.0/0']  # remove default route - can be parameter
    if '::/0' in results:
        del results ['::/0']  # similarly for IPv6
    return results


def dump_prefixes_to_text_file(ipasn_data, out_text_file_name, orig_mrt_name, debug_write_sets=False):
    if IS_PYTHON2:
        fw = open(out_text_file_name, 'wt')
    else:
        fw = open(out_text_file_name, 'wt', encoding='ASCII')
    fw.write('; IP-ASN32-DAT file\n; Original file : %s\n' % orig_mrt_name)
    n4, n6 = 0, 0
    for prefix, origin in ipasn_data.items():
        n6 += 1 if ':' in prefix else 0
        n4 += 0 if ':' in prefix else 1
    assert n4 + n6 == len(ipasn_data)
    fw.write('; Converted on  : %s\n; Prefixes-v4   : %s\n; Prefixes-v6   : %s\n; \n' % (asctime(), n4, n6))
    for prefix, origin in ipasn_data.items():
        if not debug_write_sets and isinstance(origin, set):
            origin = list(origin)[0]  # get an AS randomly, or the only AS if just one, from the set
        fw.write('%s\t%s\n' % (prefix, origin))
    fw.close()



def dump_prefixes_to_binary_file(ipasn_data, out_bin_file_name, orig_mrt_name, extra_comments=""):
    # todo: this funciton writes the binary output (tested in Py2 & 3). however, can the reader read it? :)
    fw = open(out_bin_file_name, 'wb')
    # write common header
    fw.write(b'PYASN')  # magic header
    fw.write(b'\x01')  # binary format version 1 - IPv4
    fw.write(pack('I', 0))  # number of records; will need to be updated at the end.

    # let's store comments and the name of the input file in the binary; good for debugging. max 500 bytes.
    comments = "Created <%s>, from: %s. %s" % (asctime(), orig_mrt_name, extra_comments)
    if not IS_PYTHON2:
        comments = comments.encode('ASCII', errors='replace')  # convert to bytes
    comments = comments[:499] + b'\0'  # trim, terminate
    fw.write(pack('h', len(comments)))
    fw.write(comments)

    n = 0
    for prefix, origin in ipasn_data.items():
        if isinstance(origin, set):
            origin = list(origin)[0]  # get an AS randomly, or the only AS if just one, from the set
        network, mask = prefix.split('/')
        assert ':' not in network   # TODO-IPv6: need more bytes here
        fw.write(inet_aton(network))
        fw.write(pack('B', int(mask)))
        fw.write(pack('I', origin))
        n += 1

    fw.write(b'\0'*9)  # write one terminating zero record
    fw.seek(6)
    fw.write(pack('I', n))  # update number of records at start of file.
    fw.close()


def is_asn_bogus(asn):
    """Returns True if the ASN is in the private-use or reserved list of ASNs"""
    # References:
    #       IANA:  http://www.iana.org/assignments/as-numbers/as-numbers.xhtml
    #       RFCs:  rfc1930, rfc6996, rfc7300, rfc5398
    #       Cymru: http://www.team-cymru.org/Services/Bogons/, http://www.cymru.com/BGP/asnbogusrep.html
    #       WHOIS: https://github.com/rfc1036/whois   -- in the program source
    #       CIDR-Report: http://www.cidr-report.org/as2.0/reserved-ases.html
    # Note that the full list of unallocated and bogus ASNs is long, and changes; we use the basic
    if 64198 <= asn <= 131071 or asn >= 4200000000:   # reserved & private-use-AS
        return True
    if asn >= 1000000:  # way above last currently allocated block (2014-11-02) -- might change in future
        return True
    return False


#####################################################################
# MRT headers, tables, and attributes sections
# MRT format spec at: http://tools.ietf.org/html/rfc6396
# BGP attribute spec at: http://tools.ietf.org/html/rfc4271

# HA 2015/11/19 started work on IPv6 for Table_Dump_V2

# Performance notes:
#  -this code isn't super fast, but that's OK because it's run once to convert/parse the MRT files
#  - it can be sped up perhaps by replacing some struct.unpacks(), profiling, or rewriting in C
#  - it's not a full MRT parser;  we ignore types/attributes we don't need


class MrtRecord:
    """Class for generic MRT Records. Implements common header, as well as methods for specific types"""

    # We are interested in MRT-record types Table_Dump & Table_Dump_V2, and among them in some sub-types
    TYPE_TABLE_DUMP = 12
    TYPE_TABLE_DUMP_V2 = 13
    T1_AFI_IPv4 = 1
    T1_AFI_IPv6 = 2
    T2_PEER_INDEX_TABLE = 1
    T2_RIB_IPV4_UNICAST = 2
    T2_RIB_IPV6_UNICAST = 4

    def __init__(self, header):
        self.ts, self.type, self.sub_type, self.data_len = unpack('>IHHI', header)
        self.table = None

    @staticmethod
    def next_dump_table_record(f):
        header_len = 12
        buf = f.read(header_len)  # read table-header
        if not buf:  # EOF
            return None
        #assert len(buf) == header_len
        mrt = MrtRecord(buf)
        buf = f.read(mrt.data_len)  # read table-data
        assert len(buf) == mrt.data_len
        if mrt.type == MrtRecord.TYPE_TABLE_DUMP:
            assert mrt.sub_type in (MrtRecord.T1_AFI_IPv4, MrtRecord.T1_AFI_IPv6)
            mrt.table = MrtTableDump1(buf, mrt.sub_type)
        elif mrt.type == MrtRecord.TYPE_TABLE_DUMP_V2:
            # only allow these types
            # T2_PEER_INDEX_TABLE provides BGP ID of the collector and list of peers; we don't use it
            assert mrt.sub_type in (MrtRecord.T2_PEER_INDEX_TABLE,
                                    MrtRecord.T2_RIB_IPV4_UNICAST,
                                    MrtRecord.T2_RIB_IPV6_UNICAST)
            if mrt.sub_type in (MrtRecord.T2_RIB_IPV4_UNICAST, MrtRecord.T2_RIB_IPV6_UNICAST):
                mrt.table = MrtTableDump2(buf, mrt.sub_type)
        else:
            raise Exception("MrtTableHeader received an unknown MRT table dump TYPE <%d>!" % mrt.type)
        return mrt

    def __repr__(self):
        return 'MrtTable(ts:%d, type:%d, sub-type:%d, data-len:%d, seq:%s, prefix:%s)' \
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
        # For TableDumpV2 we only use entry 0 attributes. is this OK? (DumpV1 only has single entry)
        attrs = self.table.attrs if self.type == MrtRecord.TYPE_TABLE_DUMP else self.table.entries[0].attrs
        for a in attrs:
            if a.bgp_type == BgpAttribute.ATTR_AS_PATH:
                assert not path  # only one as-path attribute in each entry
                path = a.path_detail()
        assert path
        return path


class MrtTableDump1:
    """MrtTableDump1: class to hold and parse MRT Table_Dumps records"""

    def __init__(self, buf, sub_type1):
        # TODO-IPv6: to implement. possibly need "QQ" in the unpack (16B prefix), and inet_ntop() after
        assert sub_type1 == MrtRecord.T1_AFI_IPv4
        self.view, self.seq, prefix, mask, self.status, self.orig_ts, self.peer_ip, self.peer_as, self.attr_len\
            = unpack('>HHIBBIIHH', buf[:22])
        self.s_prefix = "%s/%d" % (inet_ntoa(pack('>I', prefix)), mask)
        assert self.view == 0  # view is normally 0; its intended for when an implementation has multiple RIB views
        self._attrs = []
        self._data_buf = buf

    @property
    def attrs(self):
        # The BGP Attribute field contains the BGP attribute information for the RIB entry. Parse on demand for perf.
        if not self._attrs:
            buf = self._data_buf[22:]
            j = self.attr_len
            while j > 0:
                a = BgpAttribute(buf, is32=False)
                self._attrs.append(a)
                buf = buf[len(a):]
                j -= len(a)
                if a.bgp_type == BgpAttribute.ATTR_AS_PATH:
                    break  # slight speed optimization: we can stop parsing other attributes after ASPATH
            #assert not j and not buf  # make sure all data is used -- needs to be commented if above optimization on
        return self._attrs

    def __repr__(self):
        return 'MrtTableDump1(seq:%d, prefix:%s + sole entry [attr-len:%d, peer:%d, orig-ts:%d])' % \
            (self.seq, self.s_prefix, self.attr_len, self.peer_as, self.orig_ts)


class MrtTableDump2:
    """MrtTableDump2: class to hold and parse MRT records form Table_Dumps_V2"""

    # Main difference was support of 4-byte ASNs, and support for BGP multiprotocol extensions.
    # Also, they permit a single MRT record to encode multiple RIB table entries for a single prefix.

    def __init__(self, buf, sub_type2):
        assert sub_type2 in (MrtRecord.T2_RIB_IPV4_UNICAST, MrtRecord.T2_RIB_IPV6_UNICAST)
        self.seq, mask = unpack('>IB', buf[0:5])
        octets = (mask + 7) // 8
        if sub_type2 == MrtRecord.T2_RIB_IPV4_UNICAST:
            assert octets <= 4
            padding = bytes(4-octets) if not IS_PYTHON2 else '\0'*(4-octets)
            s_prefix = inet_ntoa(buf[5:5+octets] + padding)  # faster than IPv4address class, not sure why
        elif sub_type2 == MrtRecord.T2_RIB_IPV6_UNICAST:
            assert octets <= 16
            padding = bytes(16-octets) if not IS_PYTHON2 else '\0'*(16-octets)
            s_prefix = inet_ntop(AF_INET6, buf[5:5+octets] + padding)

        self.s_prefix = s_prefix + "/%d" % mask
        self.entry_count = unpack('>H', buf[5 + octets:7 + octets])[0]
        buf = buf[7 + octets:]
        self.entries = []
        for i in range(self.entry_count):
            e = self.T2RibEntry(buf)
            self.entries.append(e)
            break  # speed optimization - ONLY MAP FIRST; shaves 50% time
            buf = buf[len(e):]
        #assert not buf  # assert fully parsed; will now fail because of optimization, so commented

    def __repr__(self):
        return 'MrtTableDump2(seq:%d, prefix:%s, entries:%d+)' % (self.seq, self.s_prefix, len(self.entries))

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
                    if attr.bgp_type == BgpAttribute.ATTR_AS_PATH:
                        break  # speed optimization: parsing other attributes after ASPATH. shaves 30% time
                #assert not j and not data  # make sure all data is used. will fail with optimization above
            return self._attrs

        def __len__(self):
            return 8 + self.attr_len

        def __repr__(self):
            return 'T2RibEntry(attr_len:%d, peer:%d, orig_ts:%d)' % (self.attr_len, self.peer, self.orig_ts)


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
        self.flags = buf[0] if not IS_PYTHON2 else ord(buf[0])
        self.bgp_type = buf[1] if not IS_PYTHON2 else ord(buf[1])
        self._is32 = is32
        self._detail = None
        if self._has_ext_len():
            _len = unpack('>H', buf[2:4])[0]
            self.data = buf[4:4 + _len]
        else:
            _len = buf[2] if not IS_PYTHON2 else ord(buf[2])
            self.data = buf[3:3 + _len]

    def __len__(self):
        return 2 + (2 if self._has_ext_len() else 1) + len(self.data)

    def __repr__(self):
        return 'BGPAttribute(type:%d, flags:%d, data_len:%d)' % (self.bgp_type, self.flags, len(self.data))

    def path_detail(self):
        assert self.bgp_type == self.ATTR_AS_PATH
        if not self._detail:  # lazy conversion on request; speeds up TD1 parse by 20%
            self._detail = self.BgpAttrASPath(self.data, self._is32)
        return self._detail


    class BgpAttrASPath:
        # An AS_PATH has routing path information represented as ordered AS_SEQUENCEs and unordered AS_SETs.

        def __init__(self, buf, is32):
            self.pathsegs = []
            while buf:
                seg = self.BgpPathSegment(buf, is32)
                buf = buf[len(seg):]
                self.pathsegs.append(seg)

        def __repr__(self):
            return "BgpAttrASPath(%s)" % ", ".join(str(path) for path in self.pathsegs)

        @property
        def origin_as(self):
            """Returns the originating AS for this prefix - an integer if clear, a set of integers not fully unclear"""

            # To identify the originating AS for a prefix, we need to understand how the path-segments work
            #
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
            #
            # CONCLUSION:
            #  i- go to the last path segment, among the many.
            #  ii- if it's a sequence, return the last AS; if it's a set, return all ASes; callee can choose any
            #  updated 2014/11/02: changes so as not to return as bogus AS the origin

            #  assert: sequence & sets can interleave; but at least one sequence before them will be a set!
            assert self.pathsegs[0].seg_type == self.BgpPathSegment.AS_SEQUENCE

            origin = None
            for last_seg in reversed(self.pathsegs):
                if last_seg.seg_type == self.BgpPathSegment.AS_SEQUENCE:
                    # for sequence, return last AS as origin; if that's bogus, use preceding
                    for asn in reversed(last_seg.path):
                        if not is_asn_bogus(asn):
                            origin = int(asn)
                            break
                elif last_seg.seg_type == self.BgpPathSegment.AS_SET:
                    # for sets: return all non-bogus routes; the callee can choose any
                    origin = set(asn for asn in last_seg.path if not is_asn_bogus(asn))
                else:
                    raise Exception("Invalid/Legacy BGP Path Segment: %d" % last_seg.seg_type)
                # we will typically break now, except in rare cases where all of seq/set was bogus. then repeat
                if origin:
                    break

            assert origin  # eventually, should not be 0 (no asn 0), or None, or an empty set
            return origin

        class BgpPathSegment:
            AS_SET = 1  # AS_SET: unordered set of ASes a route in the UPDATE message has traversed
            AS_SEQUENCE = 2  # AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed
            AS_CONFED_SEQUENCE = 3  # legacy, appears rarely, harmelss, moved check to .origin_as(). (bug #13)
            AS_CONFED_SET = 4
            #  stats on 100,000: {1: 1196, 2: 3677845}.

            def __init__(self, data, is32):
                self.seg_type = data[0] if not IS_PYTHON2 else ord(data[0])
                cnt = data[1] if not IS_PYTHON2 else ord(data[1])
                data = data[2:]
                assert self.seg_type in (self.AS_SET, self.AS_SEQUENCE, self.AS_CONFED_SEQUENCE, self.AS_CONFED_SET)
                self.path = []
                self.as_len = 4 if is32 else 2
                for i in range(cnt):
                    asn = unpack('>I' if is32 else '>H', data[:self.as_len])[0]
                    # assert asn > 0
                    # moved to origin_as() method, to ignore when a strange asn is in the middle of an as-path;
                    # e.g. in rib.20141014.0600.bz2, 193.104.137.128/25 has [20912, 0, 50112]. won't effect the origin
                    data = data[self.as_len:]
                    self.path.append(asn)

            def __len__(self):
                return 2 + self.as_len * len(self.path)

            def __str__(self):
                # for path-sequences: sequence[as1, as2, as3], for set[as1, as2, as3]
                assert self.seg_type in (self.AS_SET, self.AS_SEQUENCE)
                s = 'sequence' if self.seg_type == self.AS_SEQUENCE else 'set'
                s += str(self.path)
                return s

            def __repr__(self):
                return "BgpPathSegment-" + str(self)
