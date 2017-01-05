#!/usr/bin/python

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

# Script to download the latest routeview bgpdata, or for a certain period
# Thanks to Vitaly Khamin (https://github.com/khamin) for the FTP code

from __future__ import print_function, division
from datetime import date, datetime
from time import time
from ftplib import FTP
from argparse import ArgumentParser
from subprocess import call
from sys import argv, exit, stdout, version_info
try:
    from pyasn import __version__
except:
    pass  # not fatal if we can't get version
if version_info[0] < 3:
    from urllib2 import urlopen
else:
    from urllib.request import urlopen


# Parse command line options
# Note: --latest might be changes to --46, instead of --4, in the future
parser = ArgumentParser(description="Script to download MRT/RIB BGP archives (from RouteViews).")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--latestv4', '-4', '--latest', action='store_true',
                   help='Grab lastest IPV4 data')
group.add_argument('--latestv6', '-6', action='store_true', help='Grab lastest IPV6 data')
group.add_argument('--latestv46', '-46', action='store_true', help='Grab lastest IPV4/V6 data')
group.add_argument('--version', action='store_true')
group.add_argument('--dates-from-file', '-f', action='store',
                   help='Grab IPV4 archives for specifc dates (one date, YYYYMMDD, per line)')
args = parser.parse_args()


def ftp_download(server, remote_dir, remote_file, local_file, print_progress=True):
    """Downloads a file from an FTP server and stores it locally"""
    ftp = FTP(server)
    ftp.login()
    ftp.cwd(remote_dir)
    if print_progress:
        print('Downloading ftp://%s/%s/%s' % (server, remote_dir, remote_file))
    filesize = ftp.size(remote_file)
    # perhaps warn before overwriting file?
    with open(local_file, 'wb') as fp:
        def recv(s):
            fp.write(s)
            recv.chunk += 1
            recv.bytes += len(s)
            if recv.chunk % 100 == 0 and print_progress:
                print('\r %.f%%, %.fKB/s' % (recv.bytes*100 / filesize,
                      recv.bytes / (1000*(time()-recv.start))), end='')
                stdout.flush()
        recv.chunk, recv.bytes, recv.start = 0, 0, time()
        ftp.retrbinary('RETR %s' % remote_file, recv)
    ftp.close()
    if print_progress:
        print('\nDownload complete.')


def find_latest_in_ftp(server, archive_root, sub_dir, print_progress=True):
    """Returns (server, filepath, filename) for the most recent file in an FTP archive"""
    if print_progress:
        print('Connecting to ftp://' + server)
    ftp = FTP(server)
    ftp.login()
    months = sorted(ftp.nlst(archive_root), reverse=True)  # e.g. 'route-views6/bgpdata/2016.12'
    filepath = '/%s/%s' % (months[0], sub_dir)
    if print_progress:
        print("Finding most recent archive in %s ..." % filepath)
    ftp.cwd(filepath)
    fls = ftp.nlst()
    if not fls:
        filepath = '/%s/%s' % (months[1], sub_dir)
        if print_progress:
            print("Finding most recent archive in %s ..." % filepath)
        ftp.cwd(filepath)
        fls = ftp.nlst()
        if not fls:
            raise LookupError("Cannot find file to download. Please report a bug on github?")
    filename = max(fls)
    ftp.close()
    return (server, filepath, filename)


def find_latest_routeviews(archive_ipv):
    # RouteViews archives are as follows:
    # ftp://archive.routeviews.org/datapath/YYYYMM/ribs/XXXX
    archive_ipv = str(archive_ipv)
    assert archive_ipv in ('4', '6', '46', '64')
    return find_latest_in_ftp(server='archive.routeviews.org',
                              archive_root='bgpdata' if archive_ipv == '4' else
                                           'route-views6/bgpdata' if archive_ipv == '6' else
                                           'route-views4/bgpdata',  # 4+6
                              sub_dir='RIBS')


if args.version:
    print("MRT/RIB downloader version %s." % __version__)


if args.latestv4 or args.latestv6 or args.latestv46:
    # Download latest RouteViews MRT/RIB archive
    srvr, rp, fn = find_latest_routeviews(4 if args.latestv4 else 6 if args.latestv6 else '46')
    ftp_download(srvr, rp, fn, fn)


if args.dates_from_file:
    # read dates from a local file and use wget to download range
    dates_to_get = []
    f = open(args.dates_from_file)
    if not f:
        print("can't open %s" % args.dates_from_file)
        exit()
    for s in f:
        if not s.strip() or s[0] == '#':
            continue
        dt = date(int(s[:4]), int(s[4:6]), int(s[6:8]))  # Dates are strangely YYYYMMDD :)
        dates_to_get.append(dt)

    for dt in dates_to_get:
        # FIXME: currently v4 only. should understand v4/v6 options, and possibly use FTP method
        url_dir = 'http://archive.routeviews.org/bgpdata/%d.%02d/RIBS/' % (dt.year, dt.month)
        print('Searching %s for %d-%02d-%02d...' % (url_dir, dt.year, dt.month, dt.day), end=' ')
        stdout.flush()

        html = str(urlopen(url_dir).read())
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
        # FIXME: Why using urllib AND wget? Can urllib do listing AND downloading? (OR ftp...)
        ret = call(['wget', '-q', url_full])  # wget in quiet mode
        print()
        ret = "" if ret == 0 else "[FAIL:%d]" % ret

        print('%s\t%s\t%s\t%s' % (dt, size, url_full, ret))
        stdout.flush()
