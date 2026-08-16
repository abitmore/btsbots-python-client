import sys
import struct
import hashlib
import ecdsa
import base58
from binascii import hexlify, unhexlify

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.backends import default_backend

#### 很多代码从 graphenelib 拷贝的
### 因为代码缺乏维护，会碰到升级后不兼容的问题

def _bytes(x):  # pragma: no branch
    """Python3 and Python2 compatibility"""
    if sys.version > "3":
        return bytes(x, "utf8")
    else:  # pragma: no cover
        return x.__bytes__()

def _is_canonical(sig):
    sig = bytearray(sig)
    return (
        not (int(sig[0]) & 0x80)
        and not (sig[0] == 0 and not (int(sig[1]) & 0x80))
        and not (int(sig[32]) & 0x80)
        and not (sig[32] == 0 and not (int(sig[33]) & 0x80))
    )

def compressedPubkey(pk):
    if not isinstance(pk, ecdsa.keys.VerifyingKey):
        order = ecdsa.SECP256k1.order
        x = pk.public_numbers().x
        y = pk.public_numbers().y
    else:  # pragma: no cover
        order = pk.curve.generator.order()
        p = pk.pubkey.point
        x = p.x()
        y = p.y()
    x_str = ecdsa.util.number_to_string(x, order)
    return _bytes(chr(2 + (y & 1))) + x_str

def recoverPubkeyParameter(message, digest, signature, pubkey):
    """Use to derive a number that allows to easily recover the
    public key from the signature
    """
    if not isinstance(message, bytes):
        message = bytes(message, "utf-8")  # pragma: no cover
    for i in range(0, 4):
            p = recover_public_key(digest, signature, i, message)
            p_comp = hexlify(compressedPubkey(p))
            pubkey_comp = hexlify(compressedPubkey(pubkey))
            if p_comp == pubkey_comp:
                return i

def recover_public_key(digest, signature, i, message=None):
    """Recover the public key from the the signature"""

    # See http: //www.secg.org/download/aid-780/sec1-v2.pdf section 4.1.6 primarily
    curve = ecdsa.SECP256k1.curve
    G = ecdsa.SECP256k1.generator
    order = ecdsa.SECP256k1.order
    yp = i % 2
    r, s = ecdsa.util.sigdecode_string(signature, order)
    # 1.1
    x = r + (i // 2) * order
    # 1.3. This actually calculates for either effectively 02||X or 03||X depending on 'k' instead of always for 02||X as specified.
    # This substitutes for the lack of reversing R later on. -R actually is defined to be just flipping the y-coordinate in the elliptic curve.
    alpha = ((x * x * x) + (curve.a() * x) + curve.b()) % curve.p()
    beta = ecdsa.numbertheory.square_root_mod_prime(alpha, curve.p())
    y = beta if (beta - yp) % 2 == 0 else curve.p() - beta
    # 1.4 Constructor of Point is supposed to check if nR is at infinity.
    R = ecdsa.ellipticcurve.Point(curve, x, y, order)
    # 1.5 Compute e
    e = ecdsa.util.string_to_number(digest)
    # 1.6 Compute Q = r^-1(sR - eG)
    Q = ecdsa.numbertheory.inverse_mod(r, order) * (s * R + (-e % order) * G)

    if message is not None:
        if not isinstance(message, bytes):
            message = bytes(message, "utf-8")  # pragma: no cover
        sigder = encode_dss_signature(r, s)
        public_key = ec.EllipticCurvePublicNumbers(
            Q.x(), Q.y(), ec.SECP256K1()
        ).public_key(default_backend())
        public_key.verify(sigder, message, ec.ECDSA(hashes.SHA256()))
        return public_key
    else:
        # Not strictly necessary, but let's verify the message for paranoia's sake.
        if not ecdsa.VerifyingKey.from_public_point(
            Q, curve=ecdsa.SECP256k1
        ).verify_digest(
            signature, digest, sigdecode=ecdsa.util.sigdecode_string
        ):  # pragma: no cover
            return None  # pragma: no cover
        return ecdsa.VerifyingKey.from_public_point(
            Q, curve=ecdsa.SECP256k1
        )  # pragma: no cover

class PrivateKey:
    @staticmethod
    def _sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def _ripemd160(data: bytes) -> bytes:
        ripemd = hashlib.new('ripemd160')
        ripemd.update(data)
        return ripemd.digest()

    @classmethod
    def generate(cls) -> "PrivateKey":
        random_seed = os.urandom(32).hex()
        return cls.generate_from_seed(random_seed)

    @classmethod
    def generate_from_seed(cls, seed: str) -> "PrivateKey":
        raw_priv = cls._sha256(seed.encode('utf-8'))
        return cls(raw_priv)

    @classmethod
    def from_wif(cls, wif_str: str) -> "PrivateKey":
        decoded = base58.b58decode(wif_str)
        priv_key_bytes = decoded[1:-4]
        checksum = decoded[-4:]
        if cls._sha256(cls._sha256(decoded[:-4]))[:4] != checksum:
            raise ValueError("WIF checksum verification failed.")
        return cls(priv_key_bytes)

    def __init__(self, private_key_bytes: bytes):
        if len(private_key_bytes) != 32:
            raise ValueError("Private key must be 32 bytes.")
        self._raw_priv = private_key_bytes
        self._sk = ecdsa.SigningKey.from_string(self._raw_priv, curve=ecdsa.SECP256k1)
        self._vk = self._sk.verifying_key
        
        pub_bytes = self._vk.to_string()
        x_bytes = pub_bytes[:32]
        y_bytes = pub_bytes[32:]
        prefix_byte = b'\x03' if y_bytes[-1] % 2 else b'\x02'
        self._compressed_pub = prefix_byte + x_bytes

    def get_wif(self) -> str:
        extended = b'\x80' + self._raw_priv
        checksum = self._sha256(self._sha256(extended))[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')

    def get_public_key(self) -> str:
        checksum = self._ripemd160(self._compressed_pub)[:4]
        return "BTS" + base58.b58encode(self._compressed_pub + checksum).decode('utf-8')

    def sign_message(self, message):
        """Sign a digest with a wif key

        :param str wif: Private key in
        """

        if not isinstance(message, bytes):
            message = bytes(message, "utf-8")

        digest = hashlib.sha256(message).digest()
        p = self._raw_priv
        cnt = 0

        p = self._raw_priv
        # 2. Convert the 32-byte stream into a large Python integer
        private_value = int.from_bytes(p, byteorder='big')
        # 3. Derive the official cryptography PrivateKey object cleanly
        private_key = ec.derive_private_key(private_value, ec.SECP256K1())
        #private_key = ec.derive_private_key(
        #    int(repr(priv_key), 16), ec.SECP256K1(), default_backend()
        #)
        public_key = private_key.public_key()
        while True:
            cnt += 1
            if not cnt % 20:  # pragma: no cover
                log.info(
                    "Still searching for a canonical signature. Tried %d times already!"
                    % cnt
                )
            order = ecdsa.SECP256k1.order
            # signer = private_key.signer(ec.ECDSA(hashes.SHA256()))
            # signer.update(message)
            # sigder = signer.finalize()
            sigder = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(sigder)
            signature = ecdsa.util.sigencode_string(r, s, order)
            # Make sure signature is canonical!
            #
            sigder = bytearray(sigder)
            lenR = sigder[3]
            lenS = sigder[5 + lenR]
            if lenR == 32 and lenS == 32:
                # Derive the recovery parameter
                #
                i = recoverPubkeyParameter(message, digest, signature, public_key)
                i += 4  # compressed
                i += 27  # compact
                break
        # pack signature
        #
        sigstr = struct.pack("<B", i)
        sigstr += signature

        return sigstr

def verify_message(message, signature, bts_pubkey_str, hashfn=hashlib.sha256):
    if not isinstance(message, bytes):
        message = bytes(message, "utf-8")
    if not isinstance(signature, bytes):  # pragma: no cover
        signature = bytes(signature, "utf-8")
    if not isinstance(message, bytes):
        raise AssertionError()
    if not isinstance(signature, bytes):
        raise AssertionError()
    try:
        digest = hashfn(message).digest()
        sig = signature[1:]
        # TODO: 4 means we use compressed keys.
        # Grapehen uses compressed keys by default even though it would still allow
        # uncompressed keys to be used. This library so far expects compressed keys
        # due to this line:
        recoverParameter = bytearray(signature)[0] - 4 - 27  # recover parameter only

        p = recover_public_key(digest, sig, recoverParameter, message)
        order = ecdsa.SECP256k1.order
        r, s = ecdsa.util.sigdecode_string(sig, order)
        sigder = encode_dss_signature(r, s)
        p.verify(sigder, message, ec.ECDSA(hashes.SHA256()))
        phex = compressedPubkey(p)
        ehex = base58.b58decode(bts_pubkey_str[3:])[:33]
        return phex == ehex
    except Exception as e:
        print(f'error in verify_message: {e}')
        return False
