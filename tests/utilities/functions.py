__author__ = 'arman'


import datetime
import os

def ipdb_date(ipasn_data_file):
    data_file = os.path.basename(ipasn_data_file)
    date_string = str(data_file).split("_")[1].split(".")[0]
    year = int(date_string[:4])
    month = int(date_string[4:6])
    day = int(date_string[6:7])
    print(year, month, day)
    return datetime.datetime(year, month, day)

