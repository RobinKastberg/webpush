#!/usr/bin/python3
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode
from ctypes import c_buffer, cdll, c_void_p, c_int, c_uint64, c_char_p, \
                   addressof, pointer, c_uint32, c_long, c_size_t, cast,\
                   pointer, POINTER
import datetime
import hashlib
import hmac
import os
import requests
import sys
import sys
import time

ssl = cdll.LoadLibrary("libssl.so")
try:
    ssl.SSL_library_init()
    ssl.OPENSSL_init_ssl.argtypes = [c_uint64, c_void_p]
    ssl.OPENSSL_init_ssl(0, None)
except:
    pass

NID_X9_62_prime256v1 = 415

# If you need one, just take it from the randomly generated ones the program outputs.
# also they should look like this, and the public one usually starts with an B.
VAPID_PUBLIC  = 'BJTazZknwKFROWVtVtRHbYkwOIXQKmFVoP7RjykWejQuQazGzPqpLAx1TwM9s1YREPgrukEmw89ekdHStt4qSzo'
VAPID_PRIVATE = 'oS7ZWu6k0dFlS0vcC4DyK43s5LZd3hE_0bhLjQkmszk'
ADDRESS       = 'example@example.com'
JWT_VALID_FOR =  86400

ssl.BN_bin2bn.argtypes = [c_void_p, c_int, c_void_p]
ssl.BN_bin2bn.restype  = c_void_p
ssl.BN_bn2bin.argtypes =  [c_void_p, c_void_p]
ssl.BN_bn2bin.restype = c_int
ssl.ECDH_compute_key.argtypes = [c_void_p, c_size_t, c_void_p, c_void_p, c_void_p]
ssl.ECDH_compute_key.restype = c_int
ssl.ECDSA_do_sign.argtypes = [c_void_p, c_int, c_void_p]
ssl.ECDSA_do_sign.restype = c_void_p
ssl.ECDSA_size.argtypes = [c_void_p]
ssl.ECDSA_size.restype = c_int
ssl.EC_GROUP_new_by_curve_name.argtypes = [c_int]
ssl.EC_GROUP_new_by_curve_name.restype =  c_void_p
ssl.EC_KEY_generate_key.argtypes = [c_void_p]
ssl.EC_KEY_generate_key.restype = c_int
ssl.EC_KEY_get0_private_key.argtypes = [c_void_p]
ssl.EC_KEY_get0_private_key.restype = c_void_p
ssl.EC_KEY_get0_public_key.restype = c_void_p
ssl.EC_KEY_new.restype = c_void_p
ssl.EC_KEY_set_group.argtypes = [c_void_p, c_void_p]
ssl.EC_KEY_set_private_key.argtypes = [c_void_p, c_void_p]
ssl.ERR_error_string.restype = c_char_p
ssl.ERR_get_error.restype = c_uint32
ssl.EVP_aes_128_gcm.restype = c_void_p
ssl.EVP_CIPHER_CTX_ctrl.argtypes = [c_void_p, c_int, c_int, c_void_p]
ssl.EVP_CIPHER_CTX_ctrl.restype  = c_int
ssl.EVP_CIPHER_CTX_new.restype = c_void_p
ssl.EVP_EncryptFinal.argtypes = [c_void_p, c_void_p, c_void_p]
ssl.EVP_EncryptFinal.restype = c_int
ssl.EVP_EncryptInit.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
ssl.EVP_EncryptUpdate.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_int]
ssl.EVP_EncryptUpdate.restype = c_int
ssl.i2o_ECPublicKey.argtypes = [c_void_p, c_void_p]
ssl.i2o_ECPublicKey.restype = c_int
ssl.o2i_ECPublicKey.argtypes = [c_void_p, c_void_p, c_long]
ssl.o2i_ECPublicKey.restype = c_void_p


CURVE = ssl.EC_GROUP_new_by_curve_name(415)
CIPHER = ssl.EVP_aes_128_gcm()


_urlsafe_b64decode = urlsafe_b64decode
_urlsafe_b64encode = urlsafe_b64encode

def urlsafe_b64decode(s):
    p = "".join(["="]*((4-(len(s)%4)%4)))
    return _urlsafe_b64decode(s+p)

def urlsafe_b64encode(s):
    res = _urlsafe_b64encode(s)
    if res.find(b"=") != -1:
        return res[:res.index(b"=")]
    else:
        return res


def hmac_sha_256(a, b):
    ctx = hmac.new(a, b, hashlib.sha256)
    return ctx.digest()

def hkdf(salt, IKM, info, L):
    return hmac_sha_256(hmac_sha_256(salt, IKM), info)[:L]

def ssl_error():
    pass
    #print(ssl.ERR_error_string(ssl.ERR_get_error(), None))


def jwt_sign(digest, private, public):

    out = c_buffer(b'\x00' * 1024)

    private_b = c_buffer(private)
    public_b = c_buffer(public)
    digest_b = c_buffer(digest)
    key = c_void_p(ssl.EC_KEY_new())
    ssl.EC_KEY_set_group(key, CURVE)
    
    ptr = c_char_p(addressof(public_b))

    ret = ssl.o2i_ECPublicKey(pointer(key), pointer(ptr), len(public_b)-1)
    ptr = c_char_p(addressof(private_b))

    bignum = ssl.BN_bin2bn(ptr, len(private_b)-1, None)
    ret = ssl.EC_KEY_set_private_key(key, bignum)
    
    written = ssl.ECDSA_size(key)
    retptr = ssl.ECDSA_do_sign(addressof(digest_b), 32, key)
    retptr = cast(retptr, POINTER(c_void_p))
    big1 = retptr[0]
    big2 = retptr[1]
    #assert ((ssl.BN_num_bits(big1)+7)//8) == 32
    #assert ((ssl.BN_num_bits(big2)+7)//8) == 32
    ret = ssl.BN_bn2bin(big1, out)
    ret2 =ssl.BN_bn2bin(big2, addressof(out)+32)

    print(urlsafe_b64encode(out[:64]))
    ssl.EC_KEY_check_key(key)
    ssl.EC_KEY_free(key)
    ssl_error()
    return urlsafe_b64encode(out[:64])

def encrypt(key, iv, plaintext):
    cCEK = c_buffer(key)
    cNONCE = c_buffer(iv)
    plaintext_b = c_buffer(b"\x00\x00" + plaintext)
    out = c_buffer(b'\x00' * 4096)

    ctx = ssl.EVP_CIPHER_CTX_new()
    ssl.EVP_EncryptInit(ctx, CIPHER, cCEK, cNONCE)
    written = c_int(4096)
    written2 = c_int(4096)

    ln = ssl.EVP_EncryptUpdate(ctx, out, pointer(written), addressof(plaintext_b), len(plaintext_b)-1)
    ln = ssl.EVP_EncryptFinal(ctx, addressof(out)+written.value, pointer(written2))
    tag = c_buffer(b'\x00' * 16)

    ssl.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag)



    cipher = out[:(written.value)]+tag[0:16]
    print([hex(x) for x in cipher])

    ssl.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
    ssl.EVP_CIPHER_CTX_free(ctx)

    return cipher

def keying(auth_secret, ua_public, as_public, as_private, salt):
    out = c_buffer(b'\x00' * 1024)

    auth_secret = urlsafe_b64decode(auth_secret)
    ua_public = urlsafe_b64decode(ua_public)
    as_public = urlsafe_b64decode(as_public)
    as_private = urlsafe_b64decode(as_private)
    salt = urlsafe_b64decode(salt)

    ua_public_b = c_buffer(ua_public)
    as_private_b = c_buffer(as_private)

    pub_key = c_void_p(ssl.EC_KEY_new())


    ssl.EC_KEY_set_group(pub_key, CURVE)

    ptr = c_void_p(addressof(ua_public_b))
    ret = ssl.o2i_ECPublicKey(pointer(pub_key), pointer(ptr), len(ua_public_b)-1)

    ptr = c_void_p(addressof(as_private_b))
    bignum = ssl.BN_bin2bn(ptr, len(as_private_b)-1, None)
    ret = ssl.EC_KEY_set_private_key(pub_key, bignum)

    ssl.EC_KEY_check_key(pub_key)
    ssl_error()
    ln = ssl.ECDH_compute_key(out, 1024, ssl.EC_KEY_get0_public_key(pub_key), pub_key, None)
    ecdh_secret = out[0:ln]

    PRK_key = hmac_sha_256(auth_secret, ecdh_secret)
    print("PRK_key", urlsafe_b64encode(PRK_key))

    IKM = hkdf(auth_secret, ecdh_secret,b"Content-Encoding: auth\0\x01", 32)
    print("IKM", urlsafe_b64encode(IKM))

    CEK   = hkdf(salt, IKM, b"Content-Encoding: aesgcm\0P-256\0\x00\x41" + ua_public + b"\x00\x41" + as_public + b"\x01" , 16)
    NONCE = hkdf(salt, IKM, b"Content-Encoding: nonce\0P-256\0\x00\x41"  + ua_public + b"\x00\x41" + as_public + b"\x01" , 12)

    print("CEK",urlsafe_b64encode(CEK))
    print("NONCE",urlsafe_b64encode(NONCE))

    ssl.EC_KEY_free(pub_key)

    return CEK, NONCE

def post_http(endpoint, encrypted, key, salt):

    basename = "/".join(endpoint.split("/")[0:3])
    headers = {"crypto-key": "keyid=p256dh;dh="+key+";p256ecdsa="+VAPID_PUBLIC,
               "encryption": "keyid=p256dh;salt="+salt,
               "content-encoding": "aesgcm",

               "Authorization": "WebPush "+vapid(basename),
               #"authorization": "vapid t="+vapid(basename)+",k="+urlsafe_b64encode(vapid_public),
               "TTL": "60"}
    r = requests.post(endpoint, headers=headers, data=encrypted)
    print(r.headers)
    print(r.status_code)
    print(r.content)

    return int(r.status_code)


def vapid(audience):
    jwt_header = b'{"typ":"JWT","alg":"ES256"}'
    print(jwt_header)
    exp = str(int(datetime.datetime.utcnow().strftime("%s")) + JWT_VALID_FOR).encode("UTF-8")
    jwt_claims = b'{"aud": "'+audience.encode("UTF-8")+b'", "exp": "'+exp+b'", "sub": "'+ADDRESS.encode("UTF-8")+b'"}'
    print(jwt_claims)

    message = urlsafe_b64encode(jwt_header) + b"." + urlsafe_b64encode(jwt_claims)
    digest  = hashlib.sha256(message).digest()
    public = urlsafe_b64decode(VAPID_PUBLIC)
    private = urlsafe_b64decode(VAPID_PRIVATE)


    jwt_signature =jwt_sign(digest, private, public)
    print( message+ b"." + jwt_signature)
    return (message+ b"." + jwt_signature).decode("UTF-8")

def generate_keypair():
    key = c_void_p(ssl.EC_KEY_new())
    ssl.EC_KEY_set_group(key, CURVE)
    ssl.EC_KEY_generate_key(key)
    out = c_buffer(b"\x00",size=65)
    outptr = c_void_p(addressof(out))
    ssl.i2o_ECPublicKey(key, pointer(outptr))

    bignum = ssl.EC_KEY_get0_private_key(key)
    out_priv = c_buffer(b"\x00",size=32)
    ret = ssl.BN_bn2bin(bignum, addressof(out_priv))
    pub  =  (bytes(out[0:65]))
    priv =  (bytes(out_priv[0:32]))

    ssl.EC_KEY_free(key)

    print("Generated keypair:", urlsafe_b64encode(pub).decode("UTF-8"), urlsafe_b64encode(priv).decode("UTF-8"))

    return (urlsafe_b64encode(pub).decode("UTF-8"), urlsafe_b64encode(priv).decode("UTF-8"))
    
    
def send_message(endpoint, message, auth, key):
    public, private = generate_keypair()
    salt    = urlsafe_b64encode(os.urandom(16)).decode("UTF-8")
    key, iv = keying(auth, key, public, private, salt)
    cipher  = encrypt(key, iv, message)
    return post_http(endpoint, cipher, public, salt)

endpoint  = sys.argv[1]
ua_public = sys.argv[2]
auth_secret= sys.argv[3]

code = send_message(endpoint, sys.argv[4].encode("UTF-8"), auth_secret, ua_public)

if code in (201,):
    sys.exit(0)
else:
    sys.exit(-1)

