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


# script to download routeview bgpdata for a certain period
# the dates of the files to be downloaded are read from a file
# v2 , 23-03-2012


from __future__ import print_function, division
from datetime import date, datetime
import subprocess
from sys import argv, exit, stdout, version_info
if version_info[0] < 3:
    from urllib2 import urlopen
else:
    from urllib.request import urlopen

if not (len(argv) == 2 and argv[1] == '--latest') and not (len(argv) == 3 and argv[1] == '--dates_from_file'):
    print('usage: %s [--dates_from_file FILEWITHDATES] | [--latest]' % (argv[0]))
    print('\n       The script downloads MRT dump files from ROUTEVIEWS for the dates specified. It requires wget.')
    exit()


dates_to_get = []
download_mode = argv[1]

if argv[1] == '--latest':
     dates_to_get.append(datetime.now().date())

if argv[1] == '--dates_from_file':
    f = open(argv[2])
    if not f:
        print("can't open %s" % argv[2])
        exit()
    for s in f:
        if not s.strip() or s[0] == '#':
            continue
        dt = date(int(s[:4]), int(s[4:6]), int(s[6:8]) )
        dates_to_get.append(dt)

for dt in dates_to_get:
    url_dir = 'http://archive.routeviews.org/bgpdata/%d.%02d/RIBS/' % (dt.year, dt.month)
    print('searching %s ...' % url_dir)
    stdout.flush()

    http = urlopen(url_dir)
    html = str(http.read())
    http.close()
    str_find = 'rib.%d%02d%02d' % (dt.year, dt.month, dt.day)

    ix = html.find(str_find + '.06')
    if ix == -1:
        ix = html.find(str_find + '.05')
        #assert ix != -1
        if ix == -1:
            print(str(dt) + '\tERROR - NOT FOUND')
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
    if download_mode == '--latest':
        ret = subprocess.call(['wget',  url_full])  # non-quiet mode
    else:
        ret = subprocess.call(['wget', '-q', url_full])  # quiet mode
    ret = "" if ret == 0 else "[FAIL:%d]" % ret

    print('%s\t%s\t%s\t%s' % (dt, size, url_full, ret))
    stdout.flush()

