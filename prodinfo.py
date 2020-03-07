from binascii import unhexlify as uhx, hexlify as hx
from asn1crypto.x509 import Certificate
from asn1crypto.pem import armor
from Crypto.Util import Counter
from Crypto.Cipher import AES
from random import randint
from glob import glob
from math import gcd
import os
import asn1

keys = ['prod.keys','keys.txt','title.keys','keys.dat']

def find_keys(p):
    search = os.path.join(p,'*')
    for i in glob(search):
        if os.path.basename(i) in keys:
            return i
    return None

def generate_ssl_rsa_kek():
    home_dir = os.path.expanduser('~')
    switch_dir = os.path.join(home_dir,'.switch')
    file_dir = os.path.dirname(os.path.realpath(__file__))
    k = find_keys(switch_dir)
    if k is None:
        k = find_keys(file_dir)
        if k is None:
            return False, 'No keys found.'

    f = open(k,'r')
    keys = f.read().replace(' ','').split('\n')
    f.close()
    if keys[-1] == '':
        keys = keys[:-1]
    keys = { i.split('=')[0]:i.split('=')[1] for i in keys }
    if 'ssl_rsa_kek' in keys:
        return keys['ssl_rsa_kek'], None

    required_keys = {}
    required_keys['ssl_rsa_kek_source_x'] = keys.get('ssl_rsa_kek_source_x')
    required_keys['ssl_rsa_kek_source_y'] = keys.get('ssl_rsa_kek_source_y')
    required_keys['master_key_00'] = keys.get('master_key_00')
    required_keys['rsa_private_kek_generation_source'] = keys.get('rsa_private_kek_generation_source')

    for i in required_keys:
        if required_keys[i] is None:
            err_msg = 'Could not generate ssl_rsa_kek\n{missing_key} is not present in {keys_file}'.format(
                    missing_key=i,keys_file=k)
            return False, err_msg

    for i in dict(required_keys):
        required_keys[i] = uhx(required_keys[i])

    unwrapped = AES.new(required_keys['master_key_00'],AES.MODE_ECB).decrypt(required_keys['rsa_private_kek_generation_source'])
    unwrapped2 = AES.new(unwrapped,AES.MODE_ECB).decrypt(required_keys['ssl_rsa_kek_source_x'])
    ssl_rsa_kek = AES.new(unwrapped2,AES.MODE_ECB).decrypt(required_keys['ssl_rsa_kek_source_y'])

    return ssl_rsa_kek, None

def to_pem(prodinfo,out=None,k=None):
    if k is None:
        k, err = generate_ssl_rsa_kek()
    if out is None:
        out = 'cert.pem'
    if type(k) is str:
        k = uhx(k)

    if not k:
        return False, err

    prod = open(prodinfo,'rb')

    prod.seek(0x0AE0)
    cert_der = prod.read(0x800)
    prod.seek(0x3AE0)
    count = Counter.new(128,initial_value=int(hx(prod.read(0x10)),16))
    dec = AES.new(k,AES.MODE_CTR,counter=count).decrypt(prod.read(0x120))

    privk = dec[:0x100]

    prod.close()
    dec = asn1.Decoder()
    dec.start(cert_der)
    dec.enter()
    dec.enter()
    dec.read() 
    dec.read()
    dec.read()
    dec.read()
    dec.read()
    dec.read()
    dec.enter()
    dec.enter()
    _,v = dec.read()
    dec.leave() 
    dec.read()
    _,v = dec.read()
    rsa_decoder = asn1.Decoder()
    rsa_decoder.start(v[1:])
    rsa_decoder.enter()
    _,N = rsa_decoder.read()
    _,E = rsa_decoder.read()

    D = int(hx(privk), 0x10)

    k = E*D - 1
    t = 0
    while not k & 1:
        k >>= 1
        t += 1
    r = k
    while True:
        g = randint(0, N)
        y = pow(g, r, N)
        if y == 1 or y == N - 1:
            continue
        for j in range(1, t):
            x = pow(y, 2, N)
            if x == 1 or x == N - 1:
                break
            y = x
        if x == 1:
            break
        elif x == N - 1:
            continue
        x = pow(y, 2, N)
        if x == 1:
            break
    p = gcd(y - 1, N)
    q = N // p
    if p < q:
        p, q = q, p
    P, Q = p, q
    dP = D % (P - 1)
    dQ = D % (Q - 1)
    lastremainder, remainder = abs(Q), abs(P)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    x = lastx * (-1 if Q < 0 else 1)
    Q_inv = x % P

    enc = asn1.Encoder()
    enc.start()
    enc.enter(0x10)
    enc.write(0)
    enc.write(N)
    enc.write(E)
    enc.write(D)
    enc.write(P)
    enc.write(Q)
    enc.write(dP)
    enc.write(dQ)
    enc.write(Q_inv)
    enc.leave()
    priv_der = enc.output()
    pem_cert = armor('CERTIFICATE',Certificate.load(cert_der).dump())
    pem_cert += armor('RSA PRIVATE KEY',Certificate.load(priv_der).dump())

    with open(out,'wb') as f:
        f.write(pem_cert)

    return out, None
