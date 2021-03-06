#include "ed25519.h"
#include "sha3.h"
#include "ge.h"

#include <string.h>
#include "sha512.h"


void ed25519_pubkey(unsigned char *public_key, const unsigned char *private_key) {
	ge_p3 A;

	unsigned char _private_key[64] = { 0 };
	//memcpy(_private_key, private_key, 64);
	//sha3_512(private_key, 32, _private_key);
	SHA512_(private_key, 32, _private_key);

	_private_key[0] &= 248;
	_private_key[31] &= 127;
	_private_key[31] |= 64;

	ge_scalarmult_base(&A, _private_key);
	ge_p3_tobytes(public_key, &A);
}

void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;

    sha3_512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}
