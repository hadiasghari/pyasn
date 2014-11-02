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

import subprocess
import random
import os
from datetime import datetime
from sys import argv, exit

TEST_RESOURCES_PATH = os.path.dirname(__file__, "../data")


def as_loopkup_teamcymru(ip, date):
    datetime_string = date.strftime("%Y-%m-%d %H:%M:%S GMT")
    # note: route-views uses UTC, and we normally download files of 06:00; thus 6:00:00 GMT should be passed to cymru
    result = subprocess.check_output(["whois",  '-h', ('%s' % 'whois.cymru.com'), ' -f %s %s' % (ip, datetime_string)])
    result = result.decode().split("|")[0].strip()
    return result if result != "NA" else None


def generate_cymru_whois_ip_to_asn_mapping(s_date):
    date = datetime.strptime(s_date, "%Y%m%d")
    mapping = {}
    for count in range(1000):
        i1 = random.randint(1, 223)
        i2 = random.randint(0, 255)
        i3 = random.randint(0, 255)
        i4 = random.randint(0, 255)

        ip = "%d.%d.%d.%d" % (i1, i2, i3, i4)
        asn = as_loopkup_teamcymru(ip, date)
        mapping[ip] = asn

    with open("cymru.map", "w") as f:
        print("saving output to: %s" % f.name)
        f.write("#Mapping based on %s" % date)
        f.write("{\n")
        for ip in mapping:
            f.write("'%s' : %s, \n" % (ip, mapping[ip]))
        f.write("}")


if len(argv) != 2:
    print("Usage: python generate_test_resources.py YYYYMMDD ")
    print("       generates a static list of random IPs to AS mappings based on team-cymru WHOIS service")
    print("       The output file can be copied to the data folder to be used by the unit tests.")
    exit()

generate_cymru_whois_ip_to_asn_mapping(argv[1])
