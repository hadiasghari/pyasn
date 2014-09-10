__author__ = 'arman'

from tests.utilities.functions import ipdb_date

TEST_RESOURCES_PATH = os.path.dirname(__file__)
IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "ipasn_20140513.dat")
STATIC_WHOIS_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "cymru.mapping.pickle")
STATIC_OLD_PYASN_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "old.pyasn.mapping")
IPASN_DB_DATE = ipdb_date(IPASN_DB_PATH)
