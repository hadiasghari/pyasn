#!/usr/bin/python

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


# MRT RIB log import  [to convert to a text IP-ASN lookup table]
# file to use per day should be of these series:
# http://archive.routeviews.org/bgpdata/2009.11/RIBS/rib.20091125.0600.bz2


from __future__ import print_function, division
from pyasn import mrtx, __version__
from bz2 import BZ2File
from gzip import GzipFile
from time import time
from sys import argv, exit, stdout
from glob import glob
from datetime import datetime, timedelta
from argparse import ArgumentParser


parser = ArgumentParser(description="Script to convert MRT/RIB archives to IPASN databases.",
                        epilog="MRT/RIB archives can be downloaded using "
                        "'pyasn_util_download.py', or directly from RouteViews (or RIPE RIS).")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--single", nargs=2, metavar=("RIBFILE", "IPASN.DAT"), action="store",
                   help="convert single file (use bz2 or gz suffix)")
group.add_argument("--dump-screen", nargs=1, metavar="RIBFILE", action="store",
                   help="parse and dump archive to screen")
group.add_argument("--bulk", nargs=2, metavar=("START-DATE", "END-DATE"), action="store",
                   help="bulk conversion (dates are Y-M-D, files need to be "
                   "named rib.xxxxxxxx.bz2 and in current directory)")
group.add_argument("--version", action="store_true")
parser.add_argument("--no-progress", action="store_true",
                    help="don't show conversion progress (with --single)")
parser.add_argument("--limit-to", type=int, metavar="N", action="store",
                    help="limit to first N records (with --dump-screen)")
# TODO: add --compress option, as we have removed --binary switch (20170103).
# FIXME: --no-progress and --limit-to should be tied to --single and --dump-screen
args = parser.parse_args()


def open_archive(fpath):
    """Open a bz2 or gzip archive."""
    mode = "rb"
    GZIP_MAGIC = b"\x1f\x8b"  # magic numbers
    BZ2_MAGIC = b"\x42\x5a\x68"
    with open(fpath, mode) as fh:
        hdr = fh.read(max(len(BZ2_MAGIC), len(GZIP_MAGIC)))
    if hdr.startswith(BZ2_MAGIC):
        return BZ2File(fpath, mode)
    elif hdr.startswith(GZIP_MAGIC):
        return GzipFile(fpath, mode)
    else:
        raise TypeError("Cannot determine file type '%s'" % fpath)


if args.version:
    print("MRT/RIB converter version %s." % __version__)

if args.single:
    f = open_archive(args.single[0])
    prefixes = mrtx.parse_mrt_file(f, print_progress=not args.no_progress)  # also skip-on-error=T?
    f.close()
    mrtx.dump_prefixes_to_text_file(prefixes, args.single[1], args.single[0])
    if not args.no_progress:
        v4, v6 = 0, 0
        for prefix in prefixes:
            v6 += 1 if ':' in prefix else 0
            v4 += 0 if ':' in prefix else 1
        print('IPASN database saved (%d IPV4 + %d IPV6 prefixes)' % (v4, v6))

if args.dump_screen:
    f = open_archive(args.dump_screen[0])
    mrtx.dump_screen_mrt_file(f, limit_to=args.limit_to, screen=stdout)
    f.close()

if args.bulk:
    try:
        dt = datetime.strptime(args.bulk[0], '%Y-%m-%d').date()  # TODO:
        dt_end = datetime.strptime(args.bulk[1], '%Y-%m-%d').date()
    except ValueError:
        print("ERROR: malformed date, try YYYY-MM-DD")
        exit()
    print("Starting bulk RIB conversion, from %s to %s..." % (dt, dt_end))
    stdout.flush()
    while dt <= dt_end:
        # for each day, process first file named "rib.YYYYMMDD.xxxx.bz2". (what about .gz?)
        # this is default filename used by routeviews and downloaded by pyasn_wget_rib.py
        files = glob("rib.%4d%02d%02d.????.bz2" % (dt.year, dt.month, dt.day))
        if not files:
            dt += timedelta(1)
            continue
        if len(files) > 1:
            print("warning: multiple files on %s, only converting first." % dt)
        dump_file = files[0]
        f = open_archive(dump_file)
        print("%s... " % dump_file[4:-4])
        stdout.flush()
        dat = mrtx.parse_mrt_file(f)
        f.close()
        out_file = "ipasn_%d%02d%02d.dat" % (dt.year, dt.month, dt.day)
        mrtx.dump_prefixes_to_text_file(dat, out_file, dump_file)
        dt += timedelta(1)
    #
    print('Finished!')
