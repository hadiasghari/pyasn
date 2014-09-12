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

"""
    IMPORTANT: This script has to be run using python 2.
    Because the old PyASN is not python 3 compatible
"""
import sys
version = sys.version_info[0]
try:
    assert version == 2
except Exception:
    print("This script must be run using python version 2!")
    print("Make sure that PyASN v1.2 is installed as well.")
    exit()

import PyASN
import random
from sys import argv, exit
from struct import pack, unpack
from socket import inet_aton, inet_ntoa
import cPickle as pickle
import gzip
import os


def generate_pyasn_v1_2_ip_to_asn_mapping(pyasn_db, size):
    mapping = {}
    asndb = PyASN.new(pyasn_db)
    filename = os.path.basename(pyasn_db).split('.')[0]
    size = int(size)
    while len(mapping) < size:
        i1 = random.randint(1, 223)
        i2 = random.randint(0, 255)
        i3 = random.randint(0, 255)
        i4 = random.randint(0, 255)

        sip = "%d.%d.%d.%d" % (i1, i2, i3, i4)
        ip = unpack('>I', inet_aton(sip))[0]  # for efficient, store ip as 32-bit-int
        mapping[ip] = asndb.Lookup(sip)

    f = gzip.open("pyasn_v1.2__%s__sample_%d.pickle.gz" % (filename, size), "wb")
    pickle.dump(mapping, f)
    f.close()


if len(argv) != 3:
    print("Usage: python generate_old_pyasn_mapping.py <PYASN_DB_FILE> <number_records_to_generate>")
    print("       generates a static list of random IPs to AS mappings based on PyASN-1.2")
    print("       The output file can be copied to the data folder to be used by the unit tests.")
    exit()

generate_pyasn_v1_2_ip_to_asn_mapping(argv[1], argv[2])