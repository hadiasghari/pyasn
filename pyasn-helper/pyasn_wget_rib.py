# script to download routeview bgpdata for a certain period
# the dates of the files to be downloaded are read from a file
# v2 , 23-03-2012

import urllib2
import datetime
import subprocess
import sys


if len(sys.argv) != 2:
    print 'usage: %s FILEWITHDATES' % (sys.argv[0])
    sys.exit()

f = open(sys.argv[1])
if not f:
    print "can't open %s" % sys.argv[1]
    sys.exit()

for s in f:
    if not s.strip(): 
        break
    if s[0]=='#': 
        continue
    dt = datetime.date(int(s[:4]), int(s[4:6]), int(s[6:8]) )
    
    url_dir = 'http://archive.routeviews.org/bgpdata/%d.%02d/RIBS/' % (dt.year, dt.month)
    print 'searching %s ...' % url_dir
    sys.stdout.flush()

    http = urllib2.urlopen(url_dir)
    html = http.read()
    http.close()
    str_find = 'rib.%d%02d%02d' % (dt.year, dt.month, dt.day)

    ix = html.find(str_find + '.06')
    if ix == -1:
        ix = html.find(str_find + '.05')
        #assert ix != -1
        if ix == -1:
            print str(dt) + '\tERROR - NOT FOUND'
            dt += datetime.timedelta(days=1)
            continue

    fname = html[ix:ix+21]
    s = html[ix+80:ix+150]
    ix = s.find('"right"')
    assert ix != -1
    s = s[ix+8:]
    ix = s.find("</td>")
    assert ix != -1
    size = s[:ix]
    

    url_full = url_dir + fname
    ret = subprocess.call(['wget', '-q', url_full]) #quiet mode
    ret = "" if ret == 0 else "[FAIL:%d]" % ret

    print '%s\t%s\t%s\t%s' % (dt, size, url_full, ret)
    sys.stdout.flush()

    dt += datetime.timedelta(days=1)
#

