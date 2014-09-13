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
from pyasn import mrtx
import bz2
from time import time, asctime
from sys import argv, exit, stdout
from glob import glob
from datetime import datetime, timedelta

print('MRT RIB log importer v1.5')

if len(argv) != 4 or argv[1] not in ('--single', '--bulk'):
    print('Usage:  convert_rib.py  [--single  ribdump.bz2  ipasn.dat] | [--bulk START_DATE  END_DATE]')
    print('\n        This script converts MRT/RIB export (downloadable from RouteViews or RIPE RIS) to IPASN-databases')
    print('          For bulk mode, dates should be in yyyy-mm-dd format, and files saved into current folder.')
    exit()

if argv[1] == '--single':
    with bz2.BZ2File(argv[2], 'rb') as f:    
        dat = mrtx.parse_file(f)
    with open(argv[3], 'wt', encoding='ASCII') as fw:
        # todo: test encoding python 3/2
        fw.write('; IP-ASN32-DAT file\n; Original file : %s\n' % argv[2])
        fw.write('; Converted on  : %s\n; CIDRs         : %s\n; \n' % (time.asctime(), len(dat)) )
        for prefix, asn in sorted(dat.tems()):
            fw.write('%s\t%d\n' % (prefix, asn))
    print('IPASN database saved (%d CIDRs)' % len(dat))
    exit()

    
# BULK MODE!
try:
    dt = datetime.strptime(argv[1], '%Y-%m-%d').date()
    dt_end = datetime.strptime(argv[2], '%Y-%m-%d').date()
except:
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
        # print('%s no file!' % dt)
        dt += timedelta(days=1)            
        continue
    # if len(files) > 1 : give warning

    dump_file = files[0]
    with bz2.BZ2File(dump_file, 'rb') as f:
        print("%s... " % dump_file[4:-4], end="")     
        stdout.flush()
        dat = mrtx.parse_file(f)
        
    out_file = 'ipasn_%d%02d%02d.dat' % (dt.year, dt.month, dt.day)
    with open(out_file, 'wt', encoding='ASCII') as fw:
        # todo: test encoding python 3/2
        fw.write('; IP-ASN32-DAT file\n; Original file : %s\n' % dump_file)
        fw.write('; Converted on  : %s\n; CIDRs         : %s\n; \n' % (asctime(), len(dat)))
        for cidr, asn in sorted(dat.items()):
            fw.write('%s\t%d\n' % (cidr, asn))

    # stats - compute difference
    # changed = added = removed =  0
    # if dat__ is not None:
    #     added = len( set(dat.keys()) - set(dat__.keys()) )
    #     removed = len( set(dat__.keys()) - set(dat.keys()) )
    #     for k, v in dat.iteritems():
    #         if dat__.get(k, v) != v:
    #             changed += 1
    # print('=> cidrs:%d delta:(a%d d%d ch%d) @%.0fs'  % (len(dat), added, removed, changed, time()-st))
    #stdout.flush()
    #dat__ = dat

    dt += timedelta(days=1)

print('Finished!')
