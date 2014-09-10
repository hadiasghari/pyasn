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
import PyASN
import random
from sys import argv, exit


def generate_old_PyASN_ip_to_asn_mapping(pyasn_db):
    mapping = {}
    asndb = PyASN.new(pyasn_db)
    for count in range(10000):
        i1 = random.randint(1, 223)
        i2 = random.randint(0, 255)
        i3 = random.randint(0, 255)
        i4 = random.randint(0, 255)

        ip = "%d.%d.%d.%d" % (i1, i2, i3, i4)
        mapping[ip] = asndb.Lookup(ip)

    with open("old_pyasn.map", "w") as f:
        f.write("#Mapping based on <%s> data file" % pyasn_db)
        f.write("{\n")
        for ip in mapping:
            f.write("'%s' : %s, \n" % (ip, mapping[ip]))
        f.write("}")


if len(argv) != 2:
    print("Usage: python generate_old_pyasn_mapping.py <PYASN_DB_FILE>")
    print("       generates a static list of random IPs to AS mappings based on PyASN-1.2")
    print("       The output file can be copied to the data folder to be used by the unit tests.")
    exit()

generate_old_PyASN_ip_to_asn_mapping(argv[1])