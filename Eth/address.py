import binascii
import sha3
from ecdsa import SigningKey, SECP256k1

keccak = sha3.keccak_256()

priv = SigningKey.generate(curve=SECP256k1)
pub = priv.get_verifying_key().to_string()

keccak.update(pub)
address = "0x" + keccak.hexdigest()[24:]

priv_key = binascii.hexlify( priv.to_string())
pub_key = binascii.hexlify(pub)

print("Private key: " + priv_key.decode() )
print("Public key:  " + pub_key.decode() )
print("Address:     " + address)

