# Copyright (c) 2009-2017 Hadi Asghari
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
from socket import inet_ntoa, inet_aton, AF_INET, AF_INET6
from struct import unpack, pack
from time import time, asctime
from sys import stderr, version_info, stdout
from bz2 import BZ2File
from gzip import GzipFile
try:
    from collections import OrderedDict
except ImportError:
    # python 2.6 support - needs the ordereddict module
    from ordereddict import OrderedDict
try:
    from socket import inet_ntop
except ImportError:
    # inet_ntop is only available on unix
    pass

IS_PYTHON2 = (version_info[0] == 2)


def open_archive(fpath):
    """Open a bz2 or gzip archive."""
    # Thanks to Chris poliquin for this method (https://github.com/poliquin)
    mode = "rb"
    GZIP_MAGIC, BZ2_MAGIC = b"\x1f\x8b", b"\x42\x5a\x68"  # magic numbers
    with open(fpath, mode) as fh:
        hdr = fh.read(max(len(BZ2_MAGIC), len(GZIP_MAGIC)))
    if hdr.startswith(BZ2_MAGIC):
        return BZ2File(fpath, mode)
    elif hdr.startswith(GZIP_MAGIC):
        return GzipFile(fpath, mode)
    else:
        raise TypeError("Cannot determine file type '%s'" % fpath)


def parse_mrt_file(mrt_file,
                   print_progress=False,
                   skip_record_on_error=False):
    """parse_file(file, print_progress=False, skip_record_on_error=False):
Parses an MRT/RIB BGP table dump file.\n
    in: file-object or string-path to a MRT/RIB archive (.gz/.bz2)
    out: { "NETWORK/MASK" : ASN | set([Originating ASNs]) }
\n
The originating ASN is usually one; however, for some prefixes it can be a set.
\n
Both version 1 & 2 TABLE_DUMPS are supported, as well as 32bit ASNs and IPv6."""
    prefixes, t0, n = OrderedDict(), time(), 0

    if type(mrt_file) is str:
        # callee passed a string-path, open it. file will close when this method ends.
        # (we could alternatively try mrt_file.tell() to test if it's file-like.)
        mrt_file = open_archive(mrt_file)

    while True:
        mrt = MrtRecord.next_dump_table_record(mrt_file)
        if not mrt:
            # EOF
            break

        if not mrt.detail \
           or (mrt.type == mrt.TYPE_TABLE_DUMP_V2 and mrt.sub_type == MrtRecord.T2_PEER_INDEX):
            # not a prefix/as-path entry
            if print_progress:
                print('Parsing MRT/RIB archive .. ', mrt, file=stderr)
            continue

        if mrt.prefix not in prefixes:
            try:
                origin = mrt.get_first_origin_as()
                prefixes[mrt.prefix] = origin
            except IndexError:
                if skip_record_on_error:
                    if print_progress:
                        print("  WARNING: can't get_origin_as for prefix", mrt.prefix, file=stderr)
                    continue
                else:
                    raise
            except:
                print("  Exception parsing prefix record", mrt.prefix, file=stderr)
                raise  # raise it again
        else:
            # Repeated prefix, WARN if different.
            # In TD1, repeated prefixes were normal. We cared only about 'first-match'...
            # In TD2, until recently (201701), the MRT/RIB files typically didn't repeat prefixes.
            #   Recently, repetitions have resurfaced (e.g. bug #39). Such prefixes typically map
            #   to the same AS-origin, but not always (I'm not sure why)
            # Note, we check only for TDV2. On 20170102, 4 differ out of 600k prefixes.
            #   In TDv1, there were many many reptitions, bogging the conversion.
            if mrt.type == mrt.TYPE_TABLE_DUMP_V2:
                was = prefixes[mrt.prefix]
                new = mrt.get_first_origin_as(ignore_exception=True)
                if was != new and print_progress:
                    was = "{%d ASes}" % len(was) if type(was) is set else str(was)
                    new = "{%d ASes}" % len(new) if type(new) is set else str(new)
                    print("  WARNING: repeated prefix '%s' maps to different origin (%s vs %s)"
                          % (mrt.prefix, was, new), file=stderr)
        #
        n += 1
        if print_progress and n % (100000 if mrt.type == mrt.TYPE_TABLE_DUMP_V2 else 500000) == 0:
            print("  MRT record %d @%.fs" % (n, time() - t0), file=stderr)
    #
    if '0.0.0.0/0' in prefixes:
        del prefixes['0.0.0.0/0']  # remove default route - can be parameter
    if '::/0' in prefixes:
        del prefixes['::/0']  # similarly for IPv6
    return prefixes


def dump_screen_mrt_file(mrt_file, record_from=None, record_to=None, screen=stderr):
    """
    Parses and dumps an MRT/RIB archive to screen. For debugging purposes.
    """
    if type(mrt_file) is str:
        mrt_file = open_archive(mrt_file)
    print("Dumping MRT/RIB archive to screen:", file=screen)

    n = 0
    while True:
        mrt = MrtRecord.next_dump_table_record(mrt_file, optimize_parse=False)
        if not mrt:
            break  # EOF
        if mrt.type not in (mrt.TYPE_TABLE_DUMP, mrt.TYPE_TABLE_DUMP_V2):
            print("ERROR: dump_screen_mrt_file() supports only TDv1/TDv2 (type 12/13). Encountered"
                  " type %d, quitting.\n" % (mrt.TYPE_TABLE_DUMP_V2, mrt.type), file=screen)
            break

        n += 1
        if record_from and n < record_from:
            continue
        if record_to and n > record_to:
            break

        print('\nRecord #%06d:' % n, mrt, file=screen)

        if mrt.type == mrt.TYPE_TABLE_DUMP_V2 \
          and mrt.sub_type in (MrtRecord.T2_RIB_IPV4, MrtRecord.T2_RIB_IPV6):
            for i, entry in enumerate(mrt.detail.entries):
                for j, attr in enumerate(entry.attrs):
                    print("\t", "Entry %02d" % (i+1) if j == 0 else ' '*8, attr, file=screen)
            origin = mrt.get_first_origin_as(ignore_exception=True)
            print("\t => pyasn choice: AS", origin, file=screen)

        if mrt.type == mrt.TYPE_TABLE_DUMP:
            for i, attr in enumerate(mrt.detail.attrs):
                print("\t\t", attr, file=screen)
            # FIXIME: pyasn's choice origin should only be shown for first of repeated prefixes
            # origin = mrt.get_first_origin_as(ignore_exception=True)
            # print("\t => pyasn choice: AS", origin, file=stderr)


def dump_prefixes_to_file(prefixes,
                          ipasn_file_name,
                          source_description="",
                          debug_write_sets=False
                          ):
    if IS_PYTHON2:
        fw = open(ipasn_file_name, 'wt')
    else:
        fw = open(ipasn_file_name, 'wt', encoding='ASCII')
    fw.write('; IP-ASN32-DAT file\n; Original source: %s\n' % source_description)
    n6 = sum(1 for x in prefixes if ':' in x)
    n4 = len(prefixes) - n6
    fw.write('; Converted on  : %s\n; Prefixes-v4   : %s\n; Prefixes-v6   : %s\n; \n' %
             (asctime(), n4, n6))
    for prefix, origin in prefixes.items():
        if not debug_write_sets and isinstance(origin, set):
            origin = list(origin)[0]  # get an AS randomly, or the only AS if one, from the set
        fw.write('%s\t%s\n' % (prefix, origin))
    fw.close()


def dump_prefixes_to_text_file(ipasn_data,
                               out_text_file_name,
                               orig_mrt_name,
                               debug_write_sets=False
                               ):
    # NAME changed, this is for compatibility with scripts, use dump_prefixes_to_file() instead.
    dump_prefixes_to_file(ipasn_data, out_text_file_name, orig_mrt_name, debug_write_sets)


# dump_prefixes_to_binary_file():
# DEPRECATED because our binary format lacked IPv6 support, and its loader wasn't fully tested.
# In place, pyasn_util_convert has '--compress' now, and pyasn can load gzipped IPASN files.


def is_asn_bogus(asn):
    """Returns True if the ASN is in the private-use or reserved list of ASNs"""
    # References:
    #       IANA:  http://www.iana.org/assignments/as-numbers/as-numbers.xhtml
    #       RFCs:  rfc1930, rfc6996, rfc7300, rfc5398
    #       Cymru: http://www.team-cymru.org/Services/Bogons/,
    #              http://www.cymru.com/BGP/asnbogusrep.html
    #       WHOIS: https://github.com/rfc1036/whois   -- in the program source
    #       CIDR-Report: http://www.cidr-report.org/as2.0/reserved-ases.html
    # Note that the full list of unallocated and bogus ASNs is long, and changes; we use the basic
    if 64198 <= asn <= 131071 or asn >= 4200000000:   # reserved & private-use-AS
        return True
    if asn >= 1000000:  # way above last allocated block (2014-11-02) -- might change in future
        return True
    return False


#####################################################################
# MRT headers, tables, and attributes sections
# MRT format spec at: http://tools.ietf.org/html/rfc6396
# BGP attribute spec at: http://tools.ietf.org/html/rfc4271
#
# Performance notes:
#  -this code isn't super fast, but that's OK because it's run once to convert/parse the MRT files
#  - it can be sped up perhaps by replacing some struct.unpacks(), profiling, or rewriting in C
#  - it's not a full MRT parser;  we ignore types/attributes we don't need


class MrtRecord:
    """Class for generic MRT Records. Implements common header, and methods for some sub-types"""
    # We are interested in MRT-record types Table_Dump, Table_Dump_V2, and some sub-types
    TYPE_TABLE_DUMP = 12
    TYPE_TABLE_DUMP_V2 = 13
    T1_AFI_IPv4 = 1
    T1_AFI_IPv6 = 2
    T2_PEER_INDEX = 1
    T2_RIB_IPV4 = 2
    T2_RIB_IPV6 = 4

    def __init__(self, header):
        self.ts, self.type, self.sub_type, self.data_len = unpack('>IHHI', header)
        self.detail = None

    @staticmethod
    def next_dump_table_record(f, optimize_parse=True):
        header_len = 12
        buf = f.read(header_len)  # read table-header
        if not buf:  # EOF
            return None
        mrt = MrtRecord(buf)
        buf = f.read(mrt.data_len)  # read table-data
        assert len(buf) == mrt.data_len
        if mrt.type == MrtRecord.TYPE_TABLE_DUMP:
            assert mrt.sub_type in (MrtRecord.T1_AFI_IPv4, MrtRecord.T1_AFI_IPv6)
            mrt.detail = MrtTD1Record(buf, mrt.sub_type, optimize_parse)
        elif mrt.type == MrtRecord.TYPE_TABLE_DUMP_V2:
            # only allow these types
            assert mrt.sub_type in (MrtRecord.T2_PEER_INDEX,
                                    MrtRecord.T2_RIB_IPV4,
                                    MrtRecord.T2_RIB_IPV6)
            mrt.detail = MrtTD2Record(buf, mrt.sub_type, optimize_parse)
        else:
            raise Exception("MrtTableHeader got an unknown MRT table dump TYPE <%d>!" % mrt.type)
        return mrt

    def __repr__(self):
        if self.detail:
            return repr(self.detail)
        else:
            return "MrtRecord(Unknown type:%d/:%d, ts:%d, data-len:%d, prefix:%s)" \
                   % (self.type, self.ts, self.sub_type, self.data_len, self.prefix)
        return ret

    @property
    def prefix(self):
        return self.detail.prefix if self.detail else None  # CIDR/MASK string

    def get_first_origin_as(self, ignore_exception=False):
        # For TableDumpV2 we only use entry 0's attributes... (TD1 have single entry)
        try:
            path = None
            attrs = self.detail.attrs if self.type == MrtRecord.TYPE_TABLE_DUMP else \
                self.detail.entries[0].attrs
            for a in attrs:
                if a.bgp_type == BgpAttribute.ATTR_AS_PATH:
                    assert not path  # only one as-path attribute in each entry
                    path = a.path_detail()
            assert path
            return path.get_origin_as()
        except:
            if not ignore_exception:
                raise
            else:
                return "<exception>"


class MrtTD1Record:
    """MrtTD1Record: class to hold and parse MRT Table_Dumps records"""

    def __init__(self, buf, sub_type, optimize_parse=True):
        self.sub_type, self.seq, self.prefix, self.attr_len = sub_type, None, None, None
        self.view, self.seq = unpack('>HH', buf[:4])
        assert self.sub_type in (MrtRecord.T1_AFI_IPv4, MrtRecord.T1_AFI_IPv6)
        octs = 4 if self.sub_type == MrtRecord.T1_AFI_IPv4 else 16
        prefix = inet_ntoa(buf[4:4+octs]) if self.sub_type == MrtRecord.T1_AFI_IPv4 \
            else inet_ntop(AF_INET6, buf[4:4+octs])  # FIXME: ntop() on Windows?
        prefix_len, status, self.orig_ts = unpack('>BBI', buf[4+octs:10+octs])
        assert status == 1  # status octet is unused in TDv1 and SHOULD be set to 1
        # assert self.view == 0  # view is normally 0, used when having multiple RIB views
        # we ignore peer-ip - it can be 4 or 16 octets.
        self.peer_as, self.attr_len = unpack('>HH', buf[10+octs*2:14+octs*2])
        self.prefix = "%s/%d" % (prefix, prefix_len)
        self._attrs = []
        self._data_buf = buf[14+octs*2:]
        self._optimize = optimize_parse

    @property
    def attrs(self):
        # The BGP Attribute fields contains information for the RIB entry (parsed on demand)
        if not self._attrs:
            buf = self._data_buf[:]
            j = self.attr_len
            while j > 0:
                a = BgpAttribute(buf, is32=False)
                self._attrs.append(a)
                buf = buf[len(a):]
                j -= len(a)
                if a.bgp_type == BgpAttribute.ATTR_AS_PATH and self._optimize:
                    break  # slight optimization: stop parsing other attributes after ASPATH
            assert (not j and not buf) or self._optimize  # make sure all data is used
        return self._attrs

    def __repr__(self):
        ipv = "IPV4" if self.sub_type == MrtRecord.T1_AFI_IPv4 else "IPV6"
        ret = "MrtTD1Record (%s %s, attributes %dB)" % (ipv, self.prefix, self.attr_len)
        return ret


class MrtTD2Record:
    """MrtTD2Record: class to hold and parse MRT records form Table_Dumps_V2"""
    # Main difference between MTD1 and MTD2 is support of 4-byte ASNs, BGP multiprotocol
    # extensions, and that an MRT record can encode multiple table entries for one prefix.

    def __init__(self, buf, sub_type, optimize_parse=True):
        self.prefix, self.sub_type, self._optimize = None, sub_type, optimize_parse

        if self.sub_type == MrtRecord.T2_PEER_INDEX:
            # PEER_INDEX_TABLE provides BGP ID of the collector and list of peers
            self.collector, vn_len = unpack('>IH', buf[0:6])
            self.peer_count = unpack('>H', buf[6+vn_len:6+vn_len+2])[0]

        elif self.sub_type in (MrtRecord.T2_RIB_IPV4, MrtRecord.T2_RIB_IPV6):
            self.seq, mask = unpack('>IB', buf[0:5])

            octets = (mask + 7) // 8
            max_octs = 16 if sub_type == MrtRecord.T2_RIB_IPV6 else 4
            padding = bytes(max_octs - octets) if not IS_PYTHON2 else '\0'*(max_octs - octets)
            if sub_type == MrtRecord.T2_RIB_IPV4:
                s = inet_ntoa(buf[5:5+octets] + padding)  # ntoa() faster than IPAddress class
            elif sub_type == MrtRecord.T2_RIB_IPV6:
                s = inet_ntop(AF_INET6, buf[5:5+octets] + padding)  # FIXME: ntop() on Windows?
            self.prefix = s + "/%d" % mask

            self.entry_count = unpack('>H', buf[5 + octets:7 + octets])[0]
            buf = buf[7 + octets:]
            self.entries = []
            for i in range(self.entry_count):
                e = self.T2RibEntry(buf, self._optimize)
                self.entries.append(e)
                if self._optimize:
                    break  # parsing only first entry shaves 50% time
                buf = buf[len(e):]
            assert not buf or self._optimize  # assert fully parsed

        else:
            # Unknown / unsupported sub-type
            pass

    def __repr__(self):
        if self.sub_type in (MrtRecord.T2_RIB_IPV4, MrtRecord.T2_RIB_IPV6):
            ipv = "IPV4" if self.sub_type == MrtRecord.T2_RIB_IPV4 else "IPV6"
            more = "+" if self._optimize else ""
            ret = "MrtTD2Record (%s-UNICAST %s, %d%s entries)" % (ipv, self.prefix,
                                                                  len(self.entries), more)
        elif self.sub_type == MrtRecord.T2_PEER_INDEX:
            ret = "MrtTD2Record (PEER-INDEX-TABLE, collector %s, %d peers)" % (self.collector,
                                                                               self.peer_count)
        else:
            ret = "MrtTD2Record (Unknown Subtype %d)" % self.sub_type
        return ret

    class T2RibEntry:
        def __init__(self, buf, optimize):
            self.peer, self.orig_ts, self.attr_len = unpack('>HIH', buf[:8])
            self._data = buf[8: 8 + self.attr_len]
            self._attrs = []
            self._optimize = optimize

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
                    if attr.bgp_type == BgpAttribute.ATTR_AS_PATH and self._optimize:
                        break  # not parsing other attributes after ASPATH shaves 30% time
                assert (not j and not data) or self._optimize  # make sure all data is used
            return self._attrs

        def __len__(self):
            return 8 + self.attr_len

        def __repr__(self):
            return 'T2RibEntry (attr_len:%d, peer:%d, orig_ts:%d)' % (self.attr_len,
                                                                      self.peer, self.orig_ts)


class BgpAttribute:
    # BGP attributes are defined here:
    #   http://tools.ietf.org/html/rfc4271  (Section 5)
    #   https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
    # They are part of BGP UPDATE messages.
    # We are mainly interested in parsing the AS_PATH attribute.
    ATTR_AS_PATH = 2
    ATTR_NAMES = ("TYPE-0", "ORIGIN", "AS_PATH", "NEXT_HOP", "MULTI_EXIT_DISC", "LOCAL_PREF",
                  "ATOMIC_AGGREGATE", "AGGREGATOR", "COMMUNITIES", "ORIGINATOR_ID",
                  "CLUSTER_LIST", "TYPE-11", "TYPE-12", "TYPE-13", "MP_REACH_NLRI",
                  "MP_UNREACH_NLRI", "EXTENDED COMMUNITIES", "AS4_PATH", "AS4_AGGREGATOR")

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
        t = self.bgp_type
        ret = "BGPAttribute({}): ".format((self.ATTR_NAMES[t] if 0 <= t <= 18 else "TYPE-%d" % t))
        if t == self.ATTR_AS_PATH:
            ret += str(self.path_detail())
        elif 0 < len(self.data) <= 4:
            l = len(self.data)
            v = unpack('>'+'BHI'[l//2], self.data)[0]
            ret += str(v)
        else:
            ret += "%d bytes" % len(self.data)
        return ret

    def path_detail(self):
        assert self.bgp_type == self.ATTR_AS_PATH
        if not self._detail:  # lazy conversion on request; speeds up TD1 parse by 20%
            self._detail = self.BgpAttrASPath(self.data, self._is32)
        return self._detail

    class BgpAttrASPath:
        # An AS_PATH has routing path information represented as ordered AS_SEQUENCEs
        # and unordered AS_SETs.

        def __init__(self, buf, is32):
            self.pathsegs = []
            while buf:
                seg = self.BgpPathSegment(buf, is32)
                buf = buf[len(seg):]
                self.pathsegs.append(seg)

        def __repr__(self):
            return "path-%s" % ", ".join(str(path) for path in self.pathsegs)

        def get_origin_as(self):
            """Returns the originating AS for this prefix - an integer if clear,
            a set of integers not fully unclear"""
            # important change from pyasn_converter 1.2"
            #   in 1.2, we had a bug that ignored origins of as_paths ending in as_set,
            #   as well as origins of as_paths with more than three segments,
            #   and these prefixes (129 out of the total 513000 for 2014-05-23) weren't saved

            # To identify the originating AS for a prefix, this is how path-segments work:
            #
            # RFC 4271 on how AS_PATH is created
            # - when a BGP speaker advertises route to an internal peer, it shall not modify the
            #   AS_PATH
            # - when a BGP speaker advertises the route to an external peer, it updates AS_PATH
            #   attribute as follows:
            #   - if first path segment of AS_PATH is AS_SEQUENCE, the local system prepends its
            #     own ASN (leftmost)
            #     if more than 255 ASes already, prepends a new AS_SEQUENCE segment
            #   - if first path segment is AS_SET, its prepends a new AS_SEQUENCE segment to the
            #     AS_PATH,
            #     including its own AS number in that segment.
            #   - if AS_PATH is empty, it creates a AS_SEQUENCE segment, places its own AS into it
            #     and it into AS_PATH
            # - When a BGP speaker originates a route:
            #   - the speaker includes its own ASN in a path segment of type AS_SEQUENCE, in the
            #     AS_PATH attribute of
            #     UPDATE messages sent to external peers. (i.e., its ASN will be sole entry)
            #   - the originating speaker includes an empty AS_PATH attribute in UPDATE messages
            #     sent to internal peers.
            #
            # So none of the above uses AS_SET; AS_SET is used in aggregate messages.
            # - When a speaker aggregates several routes for advertisement to a particular peer,
            #   the AS_PATH of the aggregated route normally includes an AS_SET from the set of
            #   ASes the was aggregate was formed.
            # - Caveat: AS_SETs, used in route aggregation to reduce the size of the AS_PATH info
            #   by listing each ASN only once (regardless of times it appeared in multiple
            #   AS_PATHs), can cause some inaccuracies.
            #   The destinations listed can be reached through paths that traverse at least some
            #   constituent ASes.
            #   AS_SETs are sufficient to avoid routing loops; however, they may prune feasible
            #   paths. In practice, is not a problem because once an IP packet arrives at the edge
            #   of a group of ASes, the BGP speaker is likely to have more detailed path
            #   information.

            # CONCLUSION:
            #  i- go to the last path segment, among the many.
            #  ii- if it's a sequence, return the last AS;
            #      if it's a set, return all ASes; callee can choose any
            #  updated 2014/11: changes so as not to return as bogus AS the origin

            #  sequence & sets can interleave; but at least one sequence will be a set
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
                # will break here, except in rare cases where all of seq/set are bogus. then repeat
                if origin:
                    break

            assert origin  # eventually, should not be 0 (no asn 0), or None, or an empty set
            return origin

        class BgpPathSegment:
            AS_SET = 1  # unordered set of ASes a route in the UPDATE message has traversed
            AS_SEQUENCE = 2  # ordered set of ASes a route in the UPDATE message has traversed
            AS_CONFED_SEQUENCE = 3  # legacy, rare, harmelss, checked in .origin_as() (bug #13)
            AS_CONFED_SET = 4
            #  stats on 100,000: {1: 1196, 2: 3677845}.

            def __init__(self, data, is32):
                self.seg_type = data[0] if not IS_PYTHON2 else ord(data[0])
                cnt = data[1] if not IS_PYTHON2 else ord(data[1])
                data = data[2:]
                assert self.seg_type in (self.AS_SET,
                                         self.AS_SEQUENCE,
                                         self.AS_CONFED_SEQUENCE,
                                         self.AS_CONFED_SET)
                self.path = []
                self.as_len = 4 if is32 else 2
                for i in range(cnt):
                    asn = unpack('>I' if is32 else '>H', data[:self.as_len])[0]
                    # assert asn > 0
                    # moved to origin_as() method to ignore strange asns in the middle of as-path.
                    # e.g. in rib.20141014.0600.bz2, 193.104.137.128/25 has [20912, 0, 50112].
                    # won't effect the origin
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
