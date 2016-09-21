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


from __future__ import print_function, division
from datetime import date, datetime
from time import time
import ftplib
import argparse
import subprocess
from sys import argv, exit, stdout, version_info
if version_info[0] < 3:
    from urllib2 import urlopen
else:
    from urllib.request import urlopen
# FIXME: Why using urllib AND wget? Can urllib do listing AND downloading?

# Parse command line options
parser = argparse.ArgumentParser(description="Script to download MRT format bgpdata from routeviews.")

# mutually exclusive options
group = parser.add_mutually_exclusive_group()
group.add_argument('--latestv4', '-4', '--latest', action='store_true', help='Grab lastest v4 data')
group.add_argument('--latestv6', '-6', action='store_true', help='Grab lastest v6 data')
group.add_argument('--latestv46', '-46', action='store_true', help='Grab lastest v4 AND v6 data')
group.add_argument('--dates-from-file', '-f', action='store', help='Grab a specifc dates v4 data')
args = parser.parse_args()

print(args)

# ftp method for latest tables
if args.latestv4 or args.latestv6 or args.latestv46:
    # Thanks to Vitaly Khamin (https://github.com/khamin) for suggesting this method
    DOMAIN = 'archive.routeviews.org'
    print('Connecting to ftp://' + DOMAIN)
    ftp = ftplib.FTP(DOMAIN)
    ftp.login()

    # Choose correct path
    if args.latestv6: datapath = 'route-views6/bgpdata'
    elif args.latestv46: datapath = 'route-views4/bgpdata'
    else: datapath = 'bgpdata'

    months = sorted(ftp.nlst(datapath), reverse=True)
    print("Finding latest RIB file in /%s/RIBS/ ..." % months[0])
    ftp.cwd('/%s/RIBS/' % months[0])
    fls = ftp.nlst()
    if not fls:
        print("Finding latest RIB file in /%s/RIBS/ ..." % months[1])
        ftp.cwd('/%s/RIBS/' % months[1])
        fls = ftp.nlst()
        if not fls:
            print("Cannot find file to download. Please report a bug on github?")
            exit()
    filename = max(fls)
    filesize = ftp.size(filename)
    print('Downloading %s' % (filename))
    with open(filename, 'wb') as fp:
        def recv(s):
            fp.write(s)
            recv.chunk += 1
            recv.bytes += len(s)
            if recv.chunk % 100 == 0:
                print('\r %.f%%, %.fKB/s' % (recv.bytes*100 / filesize, recv.bytes / (1000*(time()-recv.start))), end='')
                stdout.flush()
        recv.chunk, recv.bytes, recv.start = 0, 0, time()
        ftp.retrbinary('RETR %s' % filename, recv)
    ftp.close()
    print('\nDownload complete.')

# read dates from a local file and use wget to download range
# FIXME: currently v4 specific

if args.dates_from_file:
    dates_to_get = []
    f = open(args.dates_from_file)
    if not f:
        print("can't open %s" % args.dates_from_file)
        exit()
    for s in f:
        if not s.strip() or s[0] == '#':
            continue
        dt = date(int(s[:4]), int(s[4:6]), int(s[6:8]) )
        dates_to_get.append(dt)

    for dt in dates_to_get:
        url_dir = 'http://archive.routeviews.org/bgpdata/%d.%02d/RIBS/' % (dt.year, dt.month)
        print('Searching %s for %d-%02d-%02d...' % (url_dir, dt.year, dt.month, dt.day), end=' ')
        stdout.flush()

        http = urlopen(url_dir)
        html = str(http.read())
        http.close()
        str_find = 'rib.%d%02d%02d' % (dt.year, dt.month, dt.day)

        ix = html.find(str_find + '.06')  # get the file saved at 6 AM for consistency
        if ix == -1:
            ix = html.find(str_find + '.05')  # if not, try 5 AM
            if ix == -1:
                ix = html.find(str_find + '.00')  # last resort, try the one saved at midnight
                if ix == -1:
                    print('=> ERROR - NOT FOUND.')
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
        print('downloading...', end=' ')
        stdout.flush()
        ret = subprocess.call(['wget', '-q', url_full])  # quiet mode
        print()
        ret = "" if ret == 0 else "[FAIL:%d]" % ret

        print('%s\t%s\t%s\t%s' % (dt, size, url_full, ret))
        stdout.flush()
