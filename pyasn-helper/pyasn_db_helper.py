# TODO: COMPLETE / convert to script / test final version on both py3 & 2 (for the bytestring/unicode stuff)

# todo: perhaps some of the other python files would also be better combinet with this

import socket, struct
import pickle, zlib, base64


def convert_ipasndb_to_binary(filename):
    f = open(filename)
    fw = open(filename+'.bin', 'wb')
    # SHOW STRUCTURE ADD HEADER-VER to binary file to show ipasn version + date
    fw.write(str.encode('PYASN'))  # magic header
    fw.write(b'\x01')  # binary format version 1
    fw.write(struct.pack('I', 0))  # number of records; will need to be updated at the end.
    nbytes = 12
    
    # let's store comments at start of text file as is in the binary file, useful for debugging, etc
    initial_comments = ""    
    for s in f:
        if s[0] != '#' and s[0] != '\n' and s[0] != ';':
            break
        initial_comments += s
    initial_comments = initial_comments.encode('ASCII', errors='replace')[:499] + b'\0'  #convert to bytes, trim, null terminate
    fw.write(struct.pack('h', len(initial_comments))) 
    fw.write(initial_comments)
    nbytes += len(initial_comments)
    
    # main loop - convert prefixes
    f.seek(0)
    nrecs = 0
    for s in f:
        if s.startswith('; START-AS-NAMES'):
            break  # finished prefix part
        if s[0] == '#' or s[0]=='\n' or s[0] == ';':
            continue 
        prefix, asn = s[:-1].split()     
        asn = int(asn)
        network, cidr = prefix.split('/')
        #network = struct.unpack('>I', socket.inet_aton(network))[0]
        cidr = int(cidr)
        nbytes += fw.write(socket.inet_aton(network))  # STORE THE INET VERSION, not INT. C code reads it like this too
        nbytes += fw.write(struct.pack('B', cidr))
        nbytes += fw.write(struct.pack('I', asn))
        nrecs += 1
    #    
    fw.write(bytes(9))  # write one zero record
    blob = ""
    # there might be as-names at the end; if so, convert them too. 
    for s in f:
        if s.startswith('; END-AS-NAMES'):
            break       
        assert s[0] == ';'
        blob.append(s[1:-1]) 
    if blob:
        blob = base64.b64decode(blob)  
        fw.write(struct.pack('I', len(blob)))  # number of bytes
        fw.write(blob)
    # almost done. update number of records at start of file.
    f.close()        
    fw.seek(6)
    fw.write(struct.pack('I', nrecs))
    fw.close()    
    return nbytes, nrecs
             

def convert_asnamelist_to_b64blob(filein, fileout):
    """convert an asn + as-name list (one per line, space after ASN, 32bits with dots)
    to the compressed-based64-asnames-dictionary (readable by pyasn)
    """
    # todo: compare this with using ANYDB regarding sizes, etc
    # todo: perhaps it's better if the function returns a string, instead of writing directly to an out-file
    # todo: Test on py2 (re utf/bytes). 
    asnames = {}
    f = open(filein, encoding='utf-8') 
    for s in f:
        asn, asname = s[:-1].split(maxsplit=1)
        if asname == '-Reserved AS-':
            continue
        asn = int(asn[2:]) if '.' not in asn else int(asn[2:asn.find('.')])*65536 +  int(asn[asn.find('.')+1:]) 
        asnames[asn] = asname
    f.close()    
        
    s = pickle.dumps(asnames)
    z = zlib.compress(s) 
    zb = base64.b64encode(z)

    fw = open(fileout, 'wb')
    fw.write(b'; START-AS-NAMES\n')
    for i in range(0, len(zb), 79):
        fw.write(b';')
        fw.write(zb[i:i+79])
        fw.write(b'\n')
    fw.write(b'; END-AS-NAMES\n')
    fw.close()
