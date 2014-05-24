#!/usr/bin/python

# MRT RIB log import  [to convert to a text IP-ASN lookup table]
# Author hadi asghari (hd dot asghari at gmail) of TUDelft.nl
# v1.0 on 25-nov-2009, v1.1 on 02-dec-2009
# v1.2 on 23-jan-2012 - add 32bit asn support
# v1.5 on 24-may-2014; python 3 support, and updated imports

# file to use per day should be of these series:
# http://archive.routeviews.org/bgpdata/2009.11/RIBS/rib.20091125.0600.bz2

from __future__ import print_function
import bz2, time, sys, sys, os, glob
from datetime import datetime, timedelta
import pyasn_mrtx  

print('MRT RIB log importer v1.5')

if len(sys.argv) != 4 or sys.argv[1].upper() not in ('SINGLE','BULK'):
    print('Usage:  convert_rib.py  [SINGLE  ribdump.bz2  ipasn.dat>] | [BULK  START_DATE  END_DATE]')    
    print('\nDownload RIBs from: http://archive.routeviews.org/bgpdata/2009.xx/RIBS/xxx.bz2')
    print('For bulk mode, dates should be in yyyy-mm-dd format, and files save into current folder.')
    sys.exit()


if sys.argv[1].upper() == 'SINGLE':
    with bz2.BZ2File(sys.argv[2], 'rb') as f:    
        dat = pyasn_mrtx.parse_file(f)
    with open(sys.argv[3], 'wt', encoding='ASCII') as fW:  
        # todo: test encoding python 3/2
        fw.write('; IP-ASN32-DAT file\n; Original file : %s\n' % sys.argv[2])
        fw.write('; Converted on  : %s\n; CIDRs         : %s\n; \n' % (time.asctime(), len(dat)) )
        for cidr_mask,asn in sorted(dat.iteritems()):
            fw.write('%s/%d\t%d\n' % (cidr_mask[0], cidr_mask[1], asn))    
    print('IPASN database saved (%d CIDRs)' % len(dat))
    sys.exit()

    
# BULK MODE!
try:
    dt = dt_rangestart = datetime.strptime(sys.argv[1], '%Y-%m-%d').date()
    dt_rangeend   = datetime.strptime(sys.argv[2], '%Y-%m-%d').date()
except:
    print('Malformed date. Try yyyy-mm-dd')
    sys.exit()        

print('Starting bulk RIB conversion, from %s to %s...'  % (dt_rangestart, dt_rangeend))
sys.stdout.flush()
st = time.time()
dat__ = None

while dt <= dt_rangeend:     
    # for each day, process first file named "rib.YYYYMMDD.xxxx.bz2". 
    # this is default filename used by routeviews and downloaded by bulk downloader
    files = glob.glob('rib.%4d%02d%02d.????.bz2' % (dt.year, dt.month, dt.day))
    if not files:
        #DEBUG: print('%s no file!' % dt)
        dt += timedelta(days=1)            
        continue
    dump_file = files[0]    
    with bz2.BZ2File(dump_file, 'rb') as f:
        print("%s... " % dump_file[4:-4], end="")     
        sys.stdout.flush()            
        dat = pyasn_mrtx.parse_file()
        
    out_file  = 'ipasn_%d%02d%02d.dat' % (dt.year, dt.month, dt.day)            
    with open(out_file, 'wt', encoding='ASCII') as fW:  
        # todo: test encoding python 3/2
        fw.write('; IP-ASN32-DAT file\n; Original file : %s\n' % dump_file)
        fw.write('; Converted on  : %s\n; CIDRs         : %s\n; \n' % (time.asctime(), len(dat)) )
        for cidr_mask,asn in sorted(dat.iteritems()):
            fw.write('%s/%d\t%d\n' % (cidr_mask[0], cidr_mask[1], asn))    

    # compute difference
    changed = added = removed =  0
    if dat__ is not None:
        added = len( set(dat.keys()) - set(dat__.keys()) )
        removed = len( set(dat__.keys()) - set(dat.keys()) )
        for k, v in dat.iteritems():
            if dat__.get(k, v) != v: 
                changed += 1
    print('=> cidrs:%d delta:(a%d d%d ch%d) @%.0fs'  % (len(dat), added, removed, changed, time.time()-st))
    sys.stdout.flush()
    dat__ = dat
    dt += timedelta(days=1)
#
print('Finished!')

