import itertools
import random
import re
import requests
import string
import struct
from base64 import *
from Crypto.Cipher import AES
from lxml import html

def xor(a, b):
    return ''.join(chr(ord(x)^ord(y)) for x,y in zip(a,b))

def trim(s):
    return ''.join(s.split())

def extract_words(s):
    return re.split(r'[^a-zA-Z]', s)

def get_url_words(url):
    h = html.fromstring(requests.get(url).text)
    parts = h.xpath('//text()')
    return [w for p in parts for w in extract_words(p) if w]

def get_wiki_corpus():
    return get_url_words('http://en.wikipedia.org/wiki/Substitution_cipher')

def get_freq(corpus):
    tot = float(len(corpus))
    return [bytes(corpus).count(bytes(chr(c))) / tot for c in range(0x100)]

class Metric(object):
    def __init__(self, ref_words, yesyes):
        self.ref_words = [w.lower() for w in ref_words]
        self.ref_freq = get_freq(''.join(self.ref_words))
        self.ref_words = set(self.ref_words)
        self.yesyes = set(yesyes)

    def metric(self, s, contiguous=True):
        f = get_freq(s.lower())
        d1 = sum((a - b)**2 for a, b in zip(f, self.ref_freq))
        d2 = sum(1 for c in s if c not in self.yesyes) / float(len(s))
        if d2 > 0:
            return 1<<29
        if not contiguous:
            return d1
        words = s.split()
        d3 = sum(1 for w in words if w in self.ref_words) / float(len(words))
        return d1 * (1 - d3)

def english_metric():
    english_words = get_wiki_corpus()
    asci = string.ascii_lowercase + string.ascii_uppercase + string.digits + ' \'".,;:!?\n/-_'
    return Metric(english_words, asci)

def break_xor(s, m, contiguous=True):
    res = []
    for key in range(0x100):
        plain = xor(s, chr(key)*len(s))
        res += [(m.metric(plain, contiguous=contiguous), plain)]
    return min(res)[1]

def popcnt(x):
    cnt = 0
    while x:
        cnt += x & 1
        x >>= 1
    return cnt

def hamming(a, b):
    return sum(popcnt(ord(x) ^ ord(y)) for x, y in zip(a,b))

def tohex(s):
    return ' '.join('%02x' % ord(c) for c in s)

def chall_1():
    s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print b64encode(s.decode('hex'))

def chall_2():
    a = '1c0111001f010100061a024b53535009181c'.decode('hex')
    b = '686974207468652062756c6c277320657965'.decode('hex')
    print xor(a,b).encode('hex')

def chall_3():
    cipher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'.decode('hex')
    res = []
    print break_xor(cipher, english_metric(), contiguous=True)

def chall_4():
    res = []
    best = 1<<29
    m = english_metric()
    for i, l in enumerate(open('4.txt').readlines()):
        c = l.strip().decode('hex')
        plain = break_xor(c, m)
        res += [(m.metric(plain), i, plain)]
    x = sorted(res)[0]
    print x[1], x[2]

def chall_6():
    m = english_metric()
    cipher = b64decode(open('6.txt').read())
    keysizes = []
    for ks in range(2, 41):
        a = cipher
        b = cipher[ks:]
        dist = hamming(a, b) / float(len(b))
        keysizes.append((dist, ks))
    res = []
    for x, ks in sorted(keysizes)[:1]:
        print 'testing keysize', x, ks
        slices = ['']*ks
        for i, c in enumerate(cipher):
            slices[i%ks] += c
        slices = [break_xor(s, m, contiguous=False) for s in slices]
        plain = ''.join(sum(itertools.izip_longest(*slices), ())[:len(cipher)])
        res.append((m.metric(plain), plain))
    print min(res)[1]

def pkcs7(s, block_size):
    pad = (block_size - (len(s) % block_size))
    return s + chr(pad) * pad

def unpkcs7(s):
    pad = ord(s[-1])
    assert pad and pad <= len(s)
    assert s[-pad:] == chr(pad)*pad
    return s[:-pad]

def aes_encrypt(s, key):
    return AES.AESCipher(key).encrypt(s)
def aes_decrypt(s, key):
    return AES.AESCipher(key).decrypt(s)

def aes_ecb_encrypt(s, key):
    s = pkcs7(s, 16)
    return ''.join(aes_encrypt(s[i:i+16], key) for i in xrange(0, len(s), 16))

def aes_ecb_decrypt(s, key):
    return unpkcs7(''.join(aes_decrypt(s[i:i+16], key) for i in xrange(0, len(s), 16)))

def aes_cbc_encrypt(s, key, iv, append_iv=False):
    s = pkcs7(s, 16)
    res = ''
    if append_iv:
        res += iv
    for i in xrange(0,len(s),16):
        block = aes_encrypt(xor(iv, s[i:i+16]), key)
        iv = block
        res += block
    return res

def aes_cbc_decrypt(s, key, iv=None):
    if iv:
        s = iv + s
    res = ''
    for i in xrange(16, len(s), 16):
        res += xor(s[i-16:i], aes_decrypt(s[i:i+16], key))
    return unpkcs7(res)

def rand_key(size):
    return ''.join(chr(random.randint(0,0xff)) for _ in xrange(size))

def chall_12():
    suffix = b64decode('''
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK
        ''')
    key = rand_key(16)
    def oracle(plain):
        return aes_ecb_encrypt(plain + suffix, key)

    empty_len = len(oracle(''))
    for i in xrange(1,1000):
        c = oracle('A'*i)
        if len(c) != empty_len:
            bs = len(c) - empty_len
            break
    print 'block size =', bs
    offset = len(oracle('A'*i)) - bs
    secret_len = offset - i
    assert secret_len == len(suffix)
    assert oracle('A'*i)[-bs:] == oracle(chr(bs) * bs)[:bs]
    res = ''
    for j in xrange(secret_len):
        block = oracle('A'*(i+j+1))[offset:offset+bs]
        assert len(block) == bs
        for c in xrange(0, 0x100):
            x = (chr(c) + res)[:bs]
            if len(x) < bs:
                x += chr(bs - len(x)) * (bs - len(x))
            if oracle(x)[:bs] == block:
                break
        else:
            assert False
        res = chr(c) + res
    print res

def chall_13():
    def parse_url(s):
        def parse_pair(kv):
            return tuple(kv.split('='))
        return dict(map(parse_pair, s.split('&')))

    def profile_for(email):
        return 'email=' + email.replace('&','').replace('=','') + '&uid=10&role=user'

    key = rand_key(16)
    def get_cookie(email):
        return aes_ecb_encrypt(profile_for(email), key)
    def is_admin(cookie):
        return parse_url(aes_ecb_decrypt(cookie, key))['role'] == 'admin'

    x = 'admin'
    x += chr(16-len(x))*(16-len(x))
    c1 = get_cookie('A'*(16 - len('email=')) + x)
    c2 = get_cookie('A'*(32 - len('email=&uid=10&role=')))
    c3 = c2[:32] + c1[16:32]
    print is_admin(c3)

def chall_14():
    suffix = b64decode('''
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK
        ''')
    _prefix_len = random.randint(1,100)
    print 'prefix_len =', _prefix_len
    prefix = rand_key(_prefix_len)
    key = rand_key(16)
    def oracle(plain):
        return aes_ecb_encrypt(prefix + plain + suffix, key)

    empty_len = len(oracle(''))
    for i in xrange(1,1000):
        c = oracle('A'*i)
        if len(c) != empty_len:
            bs = len(c) - empty_len
            break
    print 'block size =', bs
    assert bs == 16
    prefsuf_len = len(oracle('A'*i)) - bs - i
    print 'prefsuf_len =', prefsuf_len
    assert prefsuf_len == _prefix_len + len(suffix)

    def first_diff_block(a, b):
        for i in xrange(0, len(a), bs):
            if a[i:i+bs] != b[i:i+bs]:
                return i
        assert False

    prv = None
    for block_start in xrange(bs):
        a = 'a'*bs
        b = 'a'*block_start + 'b'*bs
        nxt = first_diff_block(oracle(a), oracle(b))
        if prv != None and nxt != prv:
            break
        prv = nxt
    else:
        block_start = 0
    block_start_cipher = first_diff_block(oracle('a'*block_start + 'b'*bs),
                                          oracle('a'*block_start + 'c'*bs))
    print 'block_start =', block_start
    print 'block_start_cipher =', block_start_cipher
    assert block_start_cipher == block_start + _prefix_len
    assert block_start_cipher % bs == 0

    def encrypt_block(x):
        assert len(x) == bs
        res = oracle('a' * block_start + x)[block_start_cipher:block_start_cipher+bs]
        assert res == aes_encrypt(x, key)
        return res

    prefix_len = block_start_cipher - block_start
    secret_len = prefsuf_len - prefix_len
    assert secret_len == len(suffix)
    i = bs - (prefsuf_len % bs)
    offset = prefsuf_len + i
    assert offset == len(oracle('A'*i)) - bs
    assert prefix_len == _prefix_len
    res = ''
    for j in xrange(secret_len):
        block = oracle('A'*(i+j+1))[offset:offset+bs]
        assert len(block) == bs
        for c in xrange(0, 0x100):
            x = (chr(c) + res)[:bs]
            if len(x) < bs:
                x += chr(bs - len(x)) * (bs - len(x))
            if encrypt_block(x) == block:
                break
        else:
            assert False
        res = chr(c) + res
    print res

def chall_16():
    key = rand_key(16)
    iv = rand_key(16)

    pref = 'comment1=cooking%20MCs;userdata='
    suff = ';comment2=%20like%20a%20pound%20of%20bacon'
    def enc(userdata):
        return aes_cbc_encrypt(pref + userdata.replace(';','').replace('=','') + suff,
                                key, iv, append_iv=False)

    def is_admin(cipher):
        dec = aes_cbc_decrypt(cipher, key, iv)
        print 'decrypted =', repr(dec)
        return ';admin=true;' in dec

    l = len(pref + suff)
    x = 0
    while x <= l:
        x += 16
    c = enc('A'*(x-l-1))
    actual = suff[-15:] + '\x01'
    desired = ';admin=true;\x01'
    assert len(desired) < 16
    desired = 'A'*(16 - len(desired)) + desired
    assert is_admin(c[:-32] + xor(xor(c[-32:-16], actual), desired) + c[-16:])

def chall_17():
    plains = """
        MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
        """.split()
    for plain in plains:
        key = rand_key(16)
        iv = rand_key(16)
        encrypted = aes_cbc_encrypt(b64decode(plain), key, iv, append_iv=True)

        def padding_oracle(cipher):
            try:
                x = aes_cbc_decrypt(cipher, key)
                return True
            except:
                return False

        res = ''
        for i in xrange(16, len(encrypted), 16):
            cipher_prefix = encrypted[:i+16]
            suf = ''
            for i in xrange(16):
                for c in xrange(0x100):
                    if all(padding_oracle(
                                cipher_prefix[:-32] +
                                rand_key(16 - len(suf) - 1) +
                                chr(c) +
                                xor(cipher_prefix[-16-len(suf):-16], xor(suf, chr(i+1)*i)) +
                                cipher_prefix[-16:])
                            for _ in xrange(5)):
                        break
                else:
                    assert False
                suf = chr(c ^ ord(cipher_prefix[-16-i-1]) ^ (len(suf)+1)) + suf
            res += suf
        print unpkcs7(res)

def ctr_stream(nonce, key):
    for ctr in itertools.count():
        for c in aes_encrypt(struct.pack('<QQ', nonce, ctr), key):
            yield c

def chall_18():
    cipher = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    print xor(ctr_stream(0, 'YELLOW SUBMARINE'), cipher)

def chall_20():
    m = english_metric()
    ciphers = map(b64decode, open('20.txt').read().split())
    min_len = min(map(len, ciphers))
    ciphers = [c[:min_len] for c in ciphers]
    slices = map(''.join, zip(*ciphers))
    slices = [break_xor(s, m, contiguous=False) for s in slices]
    ciphers = map(''.join, zip(*slices))
    for c in ciphers:
        print repr(c)

class MersenneTwister:
    def __init__(self, seed):
        self.index = 0
        MT = [seed]
        for i in xrange(623):
            MT.append((0x6c078965 * (MT[i] ^ (MT[i-1] >> 30)) + i) & 0xffffffff)
        self.MT = MT

    def generate(self):
        for i in xrange(624):
            y = (self.MT[i] & 0x80000000) | (self.MT[(i+1)%624] & 0x7fffffff)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.MT[i] ^= 0x9908b0df

    def rand(self):
        if self.index == 0:
            self.generate()
        y = self.MT[self.index]
        y ^= (y >> 11)
        y ^= ((y << 7) & 0x9d2c5680)
        y ^= ((y << 15) & 0xefc60000)
        y ^= (y >> 18)
        self.index = (self.index + 1) % 624
        return y

def chall_22():
    mt = MersenneTwister(20)
    for _ in xrange(10):
        print mt.rand()

def reverse_lshift_and_xor(a, b, y):
    """ solve `y = ((x << a) & b) ^ x` for x. """
    z = y & ((1<<a)-1)
    for i in xrange(a, 32):
        b1 = bool(z & (1<<(i-a)))
        bm = bool(b & (1<<i))
        b2 = bool(y & (1<<i))
        if (b1 & bm) ^ b2:
            z |= 1<<i
    return z

def reverse_rshift_xor(a, y):
    """ solve `y = (x >> a) ^ x` for x. """
    z = y & ~((1<<(32-a))-1)
    for i in xrange(32 - a - 1, -1, -1):
        b1 = bool(z & (1<<(i + a)))
        b2 = bool(y & (1<<i))
        if b1 ^ b2:
            z |= 1<<i
    return z

def untamper(y):
    """ reverse the MT tamper operation. """
    y = reverse_rshift_xor(18, y)
    y = reverse_lshift_and_xor(15, 0xefc60000, y)
    y = reverse_lshift_and_xor(7, 0x9d2c5680, y)
    y = reverse_rshift_xor(11, y)
    return y

def chall_23():
    mt = MersenneTwister(20)
    state = []
    for _ in xrange(624):
        state.append(untamper(mt.rand()))
    assert state == mt.MT

    mt2 = MersenneTwister(20)
    mt2.MT = state
    mt2.index = 0
    for _ in xrange(100):
        assert mt.rand() == mt2.rand()

def chall_27():
    key = rand_key(16)
    iv = key
    plain = 'a'*48
    enc = aes_cbc_encrypt(plain, key, iv, append_iv=False)

    def decryption_oracle(cipher):
        return aes_cbc_decrypt(cipher, key, iv)

    for c in xrange(0x100):
        try:
            p = decryption_oracle(enc[:16] + '\0'*16 + enc[:16] + 'A'*15 + chr(c))
        except:
            pass
        else:
            k = xor(p[:16], p[32:32+16])
            assert k == key

chall_27()
