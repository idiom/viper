from zipfile import ZipFile
from cStringIO import StringIO
from Crypto.Cipher import ARC4
import xml.etree.ElementTree as ET
import hashlib


def decrypt_payload(ratdata):
    static_key = 'ALSKEOPQLFKJDUSIKSJAUIE'
    key = hashlib.sha256(ratdata[0]+static_key).hexdigest()  # Create key
    rcobj = ARC4.new(key)
    data = rcobj.decrypt(ratdata[1])
    return data


def getpassandconfig(rjar):
    jar = ZipFile(rjar)
    pw = StringIO(jar.read('password.ini')).read()  # Contains Dynamic key
    cfg = StringIO(jar.read('config.ini')).read()   # Encrypted RAT
    ratdata = (pw, cfg)
    return ratdata


def extract_properties(data):
    jtmp = StringIO()
    jtmp.write(data)
    jar = ZipFile(jtmp)
    return StringIO(jar.read('config.xml')).read()


def config(data):
    config_data = {}
    ojar = StringIO(data)
    rdata = getpassandconfig(ojar)
    propdata = extract_properties(decrypt_payload(rdata))
    root = ET.fromstring(propdata)
    for child in root:
        if child.tag == 'entry':  # Only grab entry tags
            config_data[child.attrib['key']] = child.text
    return config_data
