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

# magic numbers
GZIP_MAGIC = b'\x1f\x8b'
BZ2_MAGIC = b'\x42\x5a\x68'

print('MRT RIB log importer %s' % __version__)

if len(argv) not in (4, 5, 6) or argv[1] not in ('--single', '--bulk'):
    # todo: rewrite using argparse
    print('Usage:  pyasn_convert_rib.py  --single  ribdump.bz2  ipasn.dat(.bin) [--binary] [--no-progress]')
    print('        pyasn_convert_rib.py  --bulk START_DATE  END_DATE [--binary]')
    print('\n        This script converts MRT/RIB export (downloadable from RouteViews or RIPE RIS) to IPASN-databases')
    print('          For bulk mode, dates should be in yyyy-mm-dd format, and files saved into current folder.')
    print('          Use the binary switch to save the output in binary format.')
    exit()

binary_output = '--binary' in argv[4:]


def open_archive(fpath, mode='rb'):
    """Open a bz2 or gzip archive."""

    with open(fpath, mode) as fh:
        hdr = fh.read(max(len(BZ2_MAGIC), len(GZIP_MAGIC)))

    if hdr.startswith(BZ2_MAGIC):
        return BZ2File(fpath, mode)
    elif hdr.startswith(GZIP_MAGIC):
        return GzipFile(fpath, mode)
    else:
        raise TypeError('Unknown file type')


if argv[1] == '--single':
    f = open_archive(argv[2])
    print_progress = '--no-progress' not in argv[4:]
    dat = mrtx.parse_mrt_file(f, print_progress=print_progress)
    f.close()
    if not binary_output:
        mrtx.dump_prefixes_to_text_file(dat, argv[3], argv[2])
    else:
        mrtx.dump_prefixes_to_binary_file(dat, argv[3], argv[2])
    print('IPASN database saved (%d prefixes)' % len(dat))
    exit()

assert argv[1] == '--bulk'
try:
    dt = datetime.strptime(argv[2], '%Y-%m-%d').date()
    dt_end = datetime.strptime(argv[3], '%Y-%m-%d').date()
except ValueError:
    print('Malformed date. Try yyyy-mm-dd')
    exit()
print('Starting bulk RIB conversion, from %s to %s...' % (dt, dt_end))
stdout.flush()
st = time()

while dt <= dt_end:
    # for each day, process first file named "rib.YYYYMMDD.xxxx.bz2".
    # this is default filename used by routeviews and downloaded by pyasn_wget_rib.py
    files = glob('rib.%4d%02d%02d.????.bz2' % (dt.year, dt.month, dt.day))
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
    if not binary_output:
        out_file = 'ipasn_%d%02d%02d.dat' % (dt.year, dt.month, dt.day)
        mrtx.dump_prefixes_to_text_file(dat, out_file, dump_file)
    else:
        out_file = 'ipasn_%d%02d%02d.bin' % (dt.year, dt.month, dt.day)
        mrtx.dump_prefixes_to_binary_file(dat, out_file, dump_file)
    dt += timedelta(1)

print('Finished!')
