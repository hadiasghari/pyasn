# TODO: ADD COPYRIGHT + LICENSE / EXPLANATIONS WITH LINKS TO ORIG PROJECTS
from ._radix import Radix as _Radix
import pickle
import zlib

#"""TODO: The docstring for a module should generally list the classes, exceptions and functions 
#(and any other objects) that are exported by the module, with a one-line summary of each. """
# also:   - explain what module is used for, e.g. historical, fast local lookups
#         - how to initliaize and lookup - or the object that needs to be called
#         - and where to download the IPASNDB files (or how to convert them from the BGP MRT dumps) - or the point in documentation          


#__version__ = '1.5' ?
#__all__ = ['pyasn'] ?

        
  
class pyasn(object):  
    """TODO: The docstring for a class should summarize its behavior and list the public methods and instance variables."""
        
    def __init__(self, ipasndb, binary=False, skip_names=True): 
        """pyasn.pyasn(ipasndb, binary=False, skip_names=True)
\nCreates a new instance of pyasn       
ipasndb    = Filename of the IP-ASN-database to load
binary     = set to True if ipasndb is binary format (faster but only IPv4 support) 
skip_names = set to False to load autonomous system names if present in db (slower)
\nThe database can be a simple text file with lines of "NETWORK/BITS\ASN"
It can also be binary for faster loading, and contain AS-Names.
You can create the database files using pyasn-helper scripts from BGP-MRT-dumps.
Or download pre-made IPASNDB files from pyasn homepage."""          
        self.radix = _Radix()
        # note: this class uses functionality provided by the underlying RADIX class (implemented in C for speed); 
        #       actions such as add and delete nodes can be run on the underlying radix tree if required; that's why we expose "radix"
        self._dbfilename = ipasndb
        self._binary = binary
        self._records = self.radix.load_ipasndb(ipasndb, binary=binary)
        self._asnames = _read_asnames(self) if not skip_names else None
    #
    
    def _read_asnames(self):
        """read autonomous system names, if present from both the text and  binary db formats"""
        asnames = None 
        f = file(self.ipasndb, "rb" if self.binary else "rt")  # codec, if required for text, should be ASCII/LATIN
        if not self.binary:        
            # in the text file, asnames is stored as the dumped version of asnames dictionary; it is compressed for efficency, and stored in BASE64
            # to maintain compatibility with older pyasn, the lines are prepended with (;), and the whole section starts/ends with asnames' so load_ipasndb can skip it
            # TODO: complete and test. including if strings have unicode how it will read in py2 ?  and that base64 returns BINARY in python 3; what to do with that?
            section_names = False
            blob = [] 
            for s in f:
                if section_names and s.startswith('; END-AS-NAMES'):
                    break       
                elif section_names:
                    assert s[0]==';'
                    blob.append(s[1:-1])  # strip start and end
                elif s.startswith('; START-AS-NAMES'):
                    # perhaps for  speed, a seek at the start of the file to this section can be done, if pos saved in comment. but might be os-dep and fragile 
                    section_names = True
            if blob:
                blob = base64.b64decode(blob)  
                blob = zlib.decompress(blob)  
                asnames = pickle.loads(blob)  # use pickle over marshal; marshal might not be compatible across python versions. 
        else:
            # for binary files, at start of file, have a structure w/ *whether contains asnames* and *# records*. then we skip # of recordsx9 bytes, and go to the blob;
            # read it, unzip it, demarhasl / depickle it to asnames
            pass
        f.close()
        return asnames
            
        
    def lookup_asn(self, ip):
        """pyasn.lookup_asn(ip)\n
Returns the Autonomous System Number that has holds this IP address (as advertised on the BGP tables).
Returns None if the IP address is not found (meaning that it was not advertised on BGP, and is globlaly unrouted).
Raises ValueError if passed an invalid IP address. """
        rn = self.radix.search_best(ip)
        return rn.asn  if rn else None

    def lookup_asn_prefix(self, ip):
        """pyasn.lookup_asn_prefix(ip)\n
Returns the Autonomous System Number that has holds this IP address, as well as the actual prefix it was advertised as part of.
Returns None,None if the IP address is not found (meaning that it was not advertised on BGP, and is globlaly unrouted).
Raises ValueError if passed an invalid IP address. 
Supports IPv4 & IPv6"""
        rn = self.radix.search_best(ip)
        return (rn.asn, rn.prefix)  if rn else (None, None)
              
    # convenience functions.  todo: add docstrings
    @property
    def all_prefixes(self): 
        return self.radix.prefixes() 

    @property        
    def all_asnames(self): 
        return self._asnames.values() if self._asnames else []
        
    @property        
    def all_asns(self): 
        # todo: can cache for speed
        return set([self.lookup_asn(px.split('/')[0]) for px in self.radix.prefixes()])
        
    def get_as_prefixes(self, asn):
        # todo: can build a complete dictionary of {asn: set(prefixes)} on first call, and cache it, for next calls to the method
        return [px for px in self.radix.prefixes() if self.lookup_asn(px.split('/')[0])==asn]
                         
    def get_as_name(self, asn):
        if not self._asnames:
            raise Exception("autonomous system names not loaded from file during initialization")  # todo: or none?
        return self._asnames.get(asn, "???")                  
        
    def __repr__(self):
        names = "has as-names" if self._asnames else "no as-names"
        return "pyasn object. ipasndb: '%s' (%d prefixes; %s)" % (self._dbfilename, self._records, names)                
    
                     
   # PERSISTENCE support, use with pickle.dump(), pickle.load()
   # todo: test  persistence support with pickle.dump. also need to persist/reload ASNAMES & the two _records & _dbfilename, if not done automatically
    def __iter__(self):
        for elt in self.radix:
            yield elt
            
    def __getstate__(self):
        return [(elt.prefix, elt.asn) for elt in self]  
        
    def __setstate__(self, state):
        for prefix, asn in state:
            node = self.radix.add(prefix)
            node.asn = asn
            
    def __reduce__(self):
        return (Radix, (), self.__getstate__())

        
        