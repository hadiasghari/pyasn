#!/usr/bin/python
"""
    IMPORTANT: This script has to be run using python 2.
    Because the old PyASN is not python 3 compatible
"""
__author__ = 'arman'

import PyASN
import random
import os

from ipaddr import IPv4Address

def generate_old_PyASN_ip_to_asn_mapping():
    mapping = {}
    asndb = PyASN.new(os.path.join("..", "resources", "ipasn_20140513.dat"))
    for count in range(10000):
        i1 = random.randint(1, 255)
        i2 = random.randint(0, 255)
        i3 = random.randint(0, 255)
        i4 = random.randint(1, 255)

        ip = IPv4Address("%d.%d.%d.%d" % (i1, i2, i3, i4))
        mapping[ip.compressed] = asndb.Lookup(ip.compressed)

    with open(os.path.join("..", "resources", "old.pyasn.mapping"), "w") as f:
        f.write("{\n")
        for ip in mapping:
            f.write("%s : %s, \n" % (ip, mapping[ip]))
        f.write("}")


generate_old_PyASN_ip_to_asn_mapping()