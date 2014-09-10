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


# script to download routeview bgpdata for a certain period
# the dates of the files to be downloaded are read from a file
# v2 , 23-03-2012


from __future__ import print_function, division
import urllib2  #TODO:
import datetime
import subprocess
import sys


if len(sys.argv) != 2:
    print('usage: %s FILEWITHDATES' % (sys.argv[0]))
    sys.exit()

f = open(sys.argv[1])
if not f:
    print("can't open %s" % sys.argv[1])
    sys.exit()

for s in f:
    if not s.strip(): 
        break
    if s[0]=='#': 
        continue
    dt = datetime.date(int(s[:4]), int(s[4:6]), int(s[6:8]) )
    
    url_dir = 'http://archive.routeviews.org/bgpdata/%d.%02d/RIBS/' % (dt.year, dt.month)
    print('searching %s ...' % url_dir)
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
            print(str(dt) + '\tERROR - NOT FOUND')
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

    print('%s\t%s\t%s\t%s' % (dt, size, url_full, ret))
    sys.stdout.flush()

    dt += datetime.timedelta(days=1)
#

