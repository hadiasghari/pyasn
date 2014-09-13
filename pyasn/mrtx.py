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

"""pyasn.mrtx: module to parse MRT/RIB BGP table dumps (in order to convert them IPASN database

   pyasn.mrtx.parse_file(file_descriptor):
    
   pyasn.mrtx.MRT_* classes: internally used to hold and parse the MRT dumps.
"""



# Currently it has only IPv4 support. For IPv6 support, changes are needed. Some parts are marked in code.


# generic many places:     ##__repr__ = __str



def parse_file(file):
    """parse_file(file):
Parses an MRT/RIB dump file.\n
    in: opened dump file to use (file-object)
    out: { "NETWORK/MASK" : ASN }
\nBoth version 1 & 2 table dumps are supported, as well as 32bit ASNs.
"""  
    results = {}
    seq_no = 0
    while True:
        mrt = MrtRecord.next_dump_table_record(file)
        if not mrt:
            break

        if mrt.type == MrtRecord.TYPE_TABLE_DUMP_V2 and mrt.sub_type == MrtRecord.T2_PEER_INDEX_TABLE:
            # this record provides  provides the BGP ID of the collector, and a list of peers. we don't use it
            # if in future, more unwanted record types exist, we can skip them here
            continue

        if mrt.prefix not in results:
            # for type1, we are only interested in getting the first match, that's why we check
            # for type2, we said: "no need for code to detect asn-flips; as routeviews always takes first match". means=???
            # also, for type2: we use just entry 0. not sure if that's ok or not either
            # finaly, how do we handle multiple AS Paths? (we don't allow two in T1. not sure if it happens anyway)
            owner = mrt.get_as_path().owning_asn()
            assert owner is not None
            if not ('{' in owner or '!' in owner):
                # what are these skipped stuff? might missed subnets be because of these??
                # curly & exception. '!' is in v1 files.
                results[mrt.prefix] = int(owner)
            else:
                pass  # debug
        else:
            pass  # debug

        seq_no = 0 if (seq_no == 65535 and mrt.type == MrtRecord.TYPE_TABLE_DUMP) else seq_no + 1
        assert mrt.table_seq == seq_no
    #
    if '0.0.0.0/0' in results:
        del results['0.0.0.0/0']  # remove_default_route - can be a parameter
    return results

    
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
            assert mrt.sub_type == MrtRecord.T1_AFI_IPv4  # we want this only
            mrt.table = MrtTableDump1(buf, ip_family=4)
        elif mrt.type == MrtRecord.TYPE_TABLE_DUMP_V2:
            assert mrt.sub_type in (MrtRecord.T2_PEER_INDEX_TABLE, MrtRecord.T2_RIB_IPV4_UNICAST)  # only these
            mrt.table = MrtTableDump2(buf, ip_family=4)
        else:
            raise Exception("MrtTableHeader received an unknown MRT table dump TYPE <%d>!" % mrt.type)
        return mrt

    def __str__(self):
        return 'MrtTable {ts:%d, type:%d, sub-type:%d, data-len:%d, seq:%d, cidr:%s}' \
               % (self.ts, self.type, self.sub_type, self.data_len, self.table_seq, self.prefix)

    @property
    def prefix(self):
        return self.table.s_prefix  # for IPV4, it's a CIDR/MASK string

    @property
    def table_seq(self):
        return self.table.seq

    def get_as_path(self):
        as_path = None
        # For MRTDUMPv2 we only use entry 0 attributes. is this OK? (DumpV1 only has single entry)
        attrs = self.table.attrs if self.type == MrtRecord.TYPE_TABLE_DUMP else self.table.entries[0].attrs
        for a in attrs:
            if a.type == BgpAttribute.ATTR_AS_PATH:
                assert not as_path  # we can have only one path!
                as_path = a.attr_detail
        assert as_path
        return as_path

    @staticmethod
    def parse_attrs(data, attr_len, is32):
        # internal method for parsing attributes, used by MrtTableDump1 & MrtTableDump2
        attrs = []
        while attr_len > 0:
            a = BgpAttribute(data, is32=is32)
            data = data[len(a):]
            attr_len -= len(a)
            attrs.append(a)
        assert not attr_len and not data  # make sure all data is used
        return attrs


class MrtTableDump1:
    """MrtTableDump1: class to hold and parse MRT Table_Dumps records"""

    def __init__(self, buf, ip_family=4):
        assert ip_family == 4  # for IPv6: the prefix-size (16B instead of 4B) and the way it's handled is different

        self.view, self.seq, prefix, mask, self.status, self.orig_ts, self.peer_ip, self.peer_as, self.attr_len\
            = unpack('>HHIBBIIHH', buf[:22])

        s_prefix = '%d.%d.%d.%d' % (prefix >> 24 & 0xff, prefix >> 16 & 0xff, prefix >> 8 & 0xff, prefix & 0xff)
        assert s_prefix == inet_ntoa(pack('>I', prefix))  # temp test
        self.s_prefix = s_prefix + "/%d" % mask

        assert self.view == 0  # view is normally 0; its intended for when an implementation has multiple RIB views
        # The BGP Attribute field contains the BGP attribute information for the RIB entry.
        self.attrs = MrtRecord.parse_attrs(buf[22:], self.attr_len, is32=False)

    def __str__(self):
        return 'MrtTableDump1 {seq:%d, prefix:%s + sole entry [attr-len:%d, peer:%d, orig-ts:%d]}' % \
            (self.seq, self.s_prefix, self.attr_len, self.peer_as, self.orig_ts)


class MrtTableDump2:
    """MrtTableDump2: class to hold and parse MRT records form Table_Dumps_V2"""

    # Main difference was support of 4-byte ASNs, and support for BGP multiprotocol extensions.
    # Also, they permit a single MRT record to encode multiple RIB table entries for a single prefix.

    def __init__(self, buf, ip_family=4):
        assert ip_family == 4  # for IPv6: the prefix must be interpreted accordingly (bytes are read correctly)
        self.seq, mask = unpack('>IB', buf[0:5])

         # todo: do double check: changed this to // for py3 compatibility on 2014-09-13, and changes below
        octets = (mask + 7) // 8
        assert 0 <= octets <= 4  # more octets for ipv6
        s = ".".join([str(ord(b)) for b in buf[5: 5 + octets]])
        s_prefix = {0: '0.0.0.0', 1: s + '.0.0.0', 2: s + '.0.0', 3: s + '.0', 4: s}[octs]

        # was:
        if octets == 0:  tmpx, tmps = 5, '0.0.0.0'
        elif octets == 1:  tmpx, tmps = 6, '%d.0.0.0' % ord(buf[5])
        elif octets == 2: tmpx, tmps = 7, '%d.%d.0.0' % tuple(map(ord, buf[5:7]))
        elif octets == 3:  tmpx, tmps = 8, '%d.%d.%d.0' % tuple(map(ord, buf[5:8]))
        else: tmpx, tmps = 9, '%d.%d.%d.%d' % tuple(map(ord, buf[5:9]))
        assert tmps == s_prefix
        self.s_prefix = s_prefix + "/%d" % mask

        entry_count = unpack('>H', buf[5 + octets:7 + octets])[0]
        buf = buf[7 + octets:]
        self.entries = []
        for i in range(entry_count):
            e = self.T2RibEntry(buf)
            buf = buf[8 + e.attr_len:]
            self.entries.append(e)
        assert not buf  # assert fully parsed

    def __str__(self):
        return 'MrtTableDump2 {seq:%d, prefix:%s, entries:%d}' % (self.seq, self.s_prefix, len(self.entries))

    class T2RibEntry:
        def __init__(self, buf):
            self.peer, self.orig_ts, self.attr_len = unpack('>HIH', buf[0:8])
            self._data = buf[8: 8 + self.attr_len]
            self._attrs = None

        @property
        def attrs(self):
            if not self._attrs:  # parse on demand for speed. we typically only parse first entry anyway
                self._attrs = MrtRecord.parse_attrs(self._data, self.attr_len, is32=True)
            return self._attrs

        def __str__(self):
            return 'T2RibEntry {attr_len: %d, peer: %d, orig_ts: %d}' % (self.attr_len, self.peer, self.orig_ts)


class BgpAttribute:
    # BGP attributes are defined here:  http://tools.ietf.org/html/rfc4271  (Section 5)

    # among them, we are interested in the BGP UPDATE messages, and in a specific AS_PATH attribute of that...

    # Stats on usage in TableDumpV2 files(on approx 100.000 thousand):
    #   1/ORIGIN 24% = generated by the speaker that originates the associated routing information
    #   2/AS_PATH 24 = identifies the AS through which routing info carried in this message has passed.
    #   3/NEXT_HOP 24% = IP address of router that SHOULD be used as the next hop to the destinations listed
    #   4/MULTI_EXIT_DISC 10% = optional attribute to discriminate among multiple exit or entry points
    #   5/ATOMIC_AGGREGATE 1.5% = discretionary attribute
    #   6/AGGREGATOR 2.5% =  optional transitive attribute,
    #   7/COMMUNITIES 14% ?  (and talk of LOCAL_PREF?)
    ATTR_AS_PATH = 2

    def _has_ext_len(self):
        extended_length = (self.flags >> 4) & 0x1
        return extended_length

    def __init__(self, buf, is32):
        self.flags, self.type = unpack('>BB', buf[0:2])
        self.len = unpack('>H', buf[2:4])[0] if self._has_ext_len() else unpack('B', buf[2:3])[0]
        self.data = buf[4:self.len] if self._has_ext_len() else buf[3:self.len]
        if self.type == self.ATTR_AS_PATH:
            self.attr_detail = self.BgpAttrASPath(self.data, is32)
    
    def __len__(self):
        return len(self.data) + (4 if self._has_ext_len() else 3)

    def __str__(self):
        return 'BGPAttribute {type:%d, flags:%d, len(data):%d}' % (self.type, self.flags, len(self.data))

    class BgpAttrASPath:
        def __init__(self, buf, is32):
            self.paths = []
            while buf:
                seg = self.BgpPath(buf, is32)
                buf = buf[len(seg):]
                self.paths.append(seg)

        def __len__(self):
            return sum(map(len, self.paths))

        def __str__(self):
            return 'BgpASPath {paths:%d}' % len(self.paths)

        def get_origin_as(self):
            # todo: needs debugging
            if len(self.paths) == 1:
                assert self.paths[0].type == self.BgpPath.AS_SEQUENCE  # new check
                x = int(self.paths[0].path[-1])  # one segment; get last path of it
                assert x > 0  # negative & 0 don't make sense
                return str(x)  # was: str(x) if x < 65536 else '%d.%d' % (x >> 16, x & 0xffff) -- remvoe if ok
            elif len(self.paths) == 2 \
                    and self.paths[0].type == self.BgpPath.AS_SEQUENCE \
                    and self.paths[1].type == self.BgpPath.AS_SET:
                # new change. i'm not sure what this exactly is, but i'm guessing should be the first not latter
                x = int(self.paths[0].path[-1])
                #x = str(self.segments[1])  # new change. was this, i think it's an error
                return x
            else:
                # unclear case with > 2 segments or ... mainly in V1. debug?
                return '![paths-types: %s]!' % [p.type for p in self.paths]

        class BgpPath:
            # BGP AS PATH types. we have two:
            #    AS_SET: unordered set of ASes a route in the UPDATE message has traversed
            #    AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed
            AS_SET = 1  # stats on 100,000: {1: 1196, 2: 3677845}.
            AS_SEQUENCE = 2

            def __init__(self, data, is32):
                self.as_len = 4 if is32 else 2
                self.type, cnt = unpack('>BB', data[:2])
                data = data[2:]
                assert self.type in (self.AS_SET, self.AS_SEQUENCE)  # also 3?
                self.path = []
                for i in range(cnt):
                    asn = unpack('>I', data[:4])[0] if is32 else unpack('>H', data[:2])[0]
                    data = data[4:] if is32 else data[2:]
                    self.path.append(asn)

            def __len__(self):
                return 2 + self.as_len * len(self.path)

            def __str__(self):
                raise Exception("DONT USE STRING -- DEBUGGING")
                #s = '' if self.type == self.AS_SEQUENCE else '{' if self.type == self.AS_SET else '<<'
                # for asn in self.path:
                #     s += str(asn) + ' '
                # s = s.strip()
                # s += '' if self.type == self.AS_SEQUENCE else '}' if self.type == self.AS_SET else '>>'
                # return s
