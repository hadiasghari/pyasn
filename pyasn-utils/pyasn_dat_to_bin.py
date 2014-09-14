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

# todo: test / debug this file on py3 (and later py2)

from __future__ import print_function, division
from socket import inet_aton
from struct import pack
from sys import argv, exit
import time

if len(argv) != 2:
    print('Usage:  pyasn_dat_to_bin.py  <ipasn.dat> <ipasn.bin>')
    print('        Converts text based IPASNDB file to binary format')
    exit()

def convert_ipasn_dat_to_binary(ipasn_dat_file, ipasn_bin_file):
    """this method takes input ipasn.dat (text) file, and converts it into binary format for faster loading"""
    fw = open(ipasn_bin_file, 'wb')

    # write common header
    fw.write(str.encode('PYASN'))  # magic header
    fw.write(b'\x01')  # binary format version 1 - IPv4
    fw.write(pack('I', 0))  # number of records; will need to be updated at the end.
    nbytes = 12
    
    # let's store comments and the name of the input file in the binary; good for debugging.
    comments = "Created <%s>, from ipasn.dat: %s" % (time.actime(), ipasn_dat_file)
    comments = comments.encode('ASCII', errors='replace')[:499] + b'\0'  # convert to bytes, trim, terminate < 500 B
    fw.write(pack('h', len(comments)))
    fw.write(comments)
    nbytes += len(comments)

    # store prefixes -- main part
    with open(ipasn_dat_file) as f:
        n = 0
        for s in f:
            if s[0] == '#' or s[0]=='\n' or s[0] == ';':
                continue
            prefix, asn = s[:-1].split()
            asn = int(asn)
            network, mask = prefix.split('/')
            mask = int(mask)
            nbytes += fw.write(inet_aton(network))
            nbytes += fw.write(pack('B', mask))  # for IPv6: need more bytes here; and IP-family in header  
            nbytes += fw.write(pack('I', asn))
            n += 1

    fw.write(bytes(9))  # write one terminating zero record
    fw.seek(6)
    fw.write(pack('I', n))     # update number of records at start of file.
    fw.close()    
    return nbytes


convert_ipasn_dat_to_binary(argv[1], argv[2])