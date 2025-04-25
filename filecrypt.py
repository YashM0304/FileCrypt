
import os, json, argparse, base64
from Crypto.Protocol.KDF   import PBKDF2
from Crypto.Cipher         import AES, DES3
from Crypto.Hash           import HMAC, SHA256, SHA512
from Crypto.Util.Padding   import pad, unpad

# --- Configurable parameters ---
FIXED1 = b'ENCRYPTION'
FIXED2 = b'HMAC______'

CIPHERS = {
    '3des':  (DES3,  24),
    'aes128':(AES, 16),
    'aes256':(AES, 32),
}
HASHES = {
    'sha256': (SHA256, 32),
    'sha512': (SHA512, 64),
}

# --- Helper to derive a key via PBKDF2 ---
def derive(password, salt, iters, dklen, hashmod):
    return PBKDF2(password, salt, dkLen=dklen, count=iters, hmac_hash_module=hashmod)

# --- Encrypt ---
def encrypt(infile, outfile, pw, cipher_name, hash_name, iters):
    pw = pw.encode()
    # 1) master key
    salt = os.urandom(16)
    hashmod, hlen = HASHES[hash_name]
    master = derive(pw, salt, iters, hlen, hashmod)

    # 2) subkeys
    ciphermod, klen = CIPHERS[cipher_name]
    K_enc  = derive(master, FIXED1, 1, klen,    hashmod)
    K_hmac = derive(master, FIXED2, 1, hlen,    hashmod)

    # 3) encrypt
    iv = os.urandom(ciphermod.block_size)
    cipher = ciphermod.new(K_enc, ciphermod.MODE_CBC, iv)
    data = open(infile,'rb').read()
    ct   = cipher.encrypt(pad(data, ciphermod.block_size))

    # 4) hmac
    h = HMAC.new(K_hmac, digestmod=hashmod)
    h.update(iv+ct)
    tag = h.digest()

    # 5) write JSON header + binary blob
    header = {
      'cipher': cipher_name,
      'hash':   hash_name,
      'iters':  iters,
      'salt':   base64.b64encode(salt).decode(),
      'iv':     base64.b64encode(iv).decode()
    }
    with open(outfile,'wb') as f:
        f.write(json.dumps(header).encode() + b'\n')
        f.write(ct + tag)

    print(f"Encrypted → {outfile!r}")

# --- Decrypt ---
def decrypt(infile, outfile, pw):
    pw = pw.encode()
    raw = open(infile,'rb').read()
    hdr, body = raw.split(b'\n',1)
    meta = json.loads(hdr.decode())

    # recover params
    ciphermod, klen = CIPHERS[meta['cipher']]
    hashmod, hlen   = HASHES[meta['hash']]
    iters = meta['iters']
    salt  = base64.b64decode(meta['salt'])
    iv    = base64.b64decode(meta['iv'])

    # split tag
    ct, tag = body[:-hlen], body[-hlen:]

    # derive keys
    master = derive(pw, salt, iters, hlen, hashmod)
    K_enc  = derive(master, FIXED1, 1, klen,    hashmod)
    K_hmac = derive(master, FIXED2, 1, hlen,    hashmod)

    # verify HMAC
    h = HMAC.new(K_hmac, digestmod=hashmod)
    h.update(iv+ct)
    try:
        h.verify(tag)
    except ValueError:
        raise ValueError("Tampering detected!")

    # decrypt
    cipher = ciphermod.new(K_enc, ciphermod.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), ciphermod.block_size)
    open(outfile,'wb').write(pt)
    print(f"Decrypted → {outfile!r}")

# --- CLI ---
if __name__=='__main__':
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)

    e = sub.add_parser('encrypt')
    e.add_argument('--in',  dest='infile',  required=True)
    e.add_argument('--out', dest='outfile', required=True)
    e.add_argument('--password', required=True)
    e.add_argument('--cipher', choices=CIPHERS, required=True)
    e.add_argument('--hash',   choices=HASHES, required=True)
    e.add_argument('--iters',  type=int, required=True)

    d = sub.add_parser('decrypt')
    d.add_argument('--in',  dest='infile',  required=True)
    d.add_argument('--out', dest='outfile', required=True)
    d.add_argument('--password', required=True)

    args = p.parse_args()
    if args.cmd=='encrypt':
        encrypt(args.infile, args.outfile, args.password,
                args.cipher, args.hash, args.iters)
    else:
        decrypt(args.infile, args.outfile, args.password)
