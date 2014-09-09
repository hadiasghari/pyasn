
__author__ = 'arman'

import random
import pickle
import os

from ipaddress import IPv4Address
from utilities import functions
import resources.resources as RES


def generate_cymru_whois_ip_to_asn_mapping(date=RES.IPASN_DB_DATE):
    mapping = {}
    for count in range(1000):
        i1 = random.randint(1, 255)
        i2 = random.randint(0, 255)
        i3 = random.randint(0, 255)
        i4 = random.randint(1, 255)

        ip = IPv4Address("%d.%d.%d.%d" % (i1, i2, i3, i4))
        asn = functions.as_loopkup_teamcymru(ip.compressed, date)
        mapping[ip.compressed] = asn

    with open(os.path.join(RES.TEST_RESOURCES_PATH, "cymru.mapping.pickle"), "wb") as f:
        pickle.dump(mapping, f)



generate_cymru_whois_ip_to_asn_mapping()
