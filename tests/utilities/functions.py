__author__ = 'arman'

import datetime
import os
import subprocess


_WHOIS_TEAM_CYMRY = 'whois.cymru.com'

def ipdb_date(ipasn_data_file):
    """
        Extract and the date of the input ipasn data file as a
        datetime object where the hours, minutes and seconds are
        set to 0.
    """
    data_file = os.path.basename(ipasn_data_file)
    date_string = str(data_file).split("_")[1].split(".")[0]
    year = int(date_string[:4])
    month = int(date_string[4:6])
    day = int(date_string[6:7])
    return datetime.datetime(year, month, day)


def team_cymru_datetime_format(datetime):
    return datetime.strftime("%Y-%m-%d %H:%M:%S GMT")


def as_loopkup_teamcymru(ip, datetime_string):
    result = subprocess.check_output(["whois",  '-h', ('%s' % _WHOIS_TEAM_CYMRY), ' -f %s %s' % (ip, datetime_string)])
    result = result.decode().split("|")[0].strip()
    return result
