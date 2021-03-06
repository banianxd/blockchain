
#include <iostream>
#include <string>

#include "ed25519/ed25519.h"
#include "base16.h"

using std::cout;
using std::endl;
using std::string;


int main()
{
	unsigned char private_key[64] = { 0 }, public_key[32] = { 0 }, seed[32] = { 0 };
	string str_private_key = "11ec18b7cffacfb46c57e027bd63f6558a78ec4ee4e929c07c6d9c68eb42c218";
	str_private_key = "11ec18b7cffacfb46c57e027bd63f6558a78ec4ee4e929c07c12345678abcdef";
	cout << "prikey: \n" << str_private_key << endl;
	decode_base16(private_key, str_private_key);

	ed25519_public_key(public_key, private_key);
	string str_public_key;
	encode_base16(str_public_key, public_key, sizeof(public_key));
	cout << "pubkey: \n" << str_public_key << endl;

	unsigned char sign_prikey[64] = { 0 };
	ed25519_get_sign_private(sign_prikey, private_key);
	string str_sign_prikey;
	encode_base16(str_sign_prikey, sign_prikey, sizeof(sign_prikey));
	cout << "sign prikey: \n" << str_sign_prikey << endl;	

	/* create a random seed, and a keypair out of that seed */
	//ed25519_create_seed(seed);
	//ed25519_create_keypair(public_key, private_key, seed);
	//encode_base16(str_private_key, private_key, sizeof(private_key));
	//encode_base16(str_public_key, public_key, sizeof(public_key));
	//cout << "prikey:\n" << str_private_key << endl;
	//cout << "pubkey:\n" << str_public_key << endl;

	unsigned char signature[64];
	const unsigned char message[] = "Hello, world!";
	const int message_len = strlen((char*)message);
	/* create signature with the new keypair */
	//ed25519_sign(signature, message, message_len, public_key, private_key);
	ed25519_sign(signature, message, message_len, public_key, sign_prikey);

	string str_sign;
	encode_base16(str_sign, signature, sizeof(signature));
	cout << "sign:\n" << str_sign << endl;

	/* verify the signature with the new keypair */
	if (ed25519_verify(signature, message, message_len, public_key)) {
		printf("valid signature\n");
	}
	else {
		printf("invalid signature\n");
	}

	string str_msg = "0A24627551566B5555424B70444B526D48595777314D553855376E676F5165686E6F31363569109F0818C0843D20E80732146275696C642073696D706C65206163636F756E743A5F08011224627551566B5555424B70444B526D48595777314D553855376E676F5165686E6F3136356922350A246275516E6936794752574D4D454376585850673854334B35615A557551456351523670691A0608011A02080128C7A3889BAB20";
	str_msg = "0a24627551574a6365367663615276526d6f69665832375a74374d58474a714a666b54393950100118c0843d20e8073a5208071224627551574a6365367663615276526d6f69665832375a74374d58474a714a666b5439395052280a246275516e474b516e4c5a3474526a6f474b36416f57766d4b4365706841585345386264771001";
	str_msg = "0a24627551574a6365367663615276526d6f69665832375a74374d58474a714a666b54393950100618c0843d20e8073aab0108071224627551574a6365367663615276526d6f69665832375a74374d58474a714a666b543939505280010a2462755170714d6a4a444d6939554c7a474263337766767a7a4272656551375136455247791a587b226d6574686f64223a227472616e73666572222c22706172616d73223a7b22746f223a226275516e474b516e4c5a3474526a6f474b36416f57766d4b436570684158534538626477222c2276616c7565223a2231227d7d";
	unsigned char sz_msg[1024] = { 0 };
	decode_base16(sz_msg, str_msg);
	int msg_len = strlen((char*)sz_msg);

	ed25519_sign(signature, sz_msg, msg_len, public_key, sign_prikey);
	encode_base16(str_sign, signature, sizeof(signature));
	cout << "sign:\n" << str_sign << endl;

	if (ed25519_verify(signature, sz_msg, msg_len, public_key)) {
		printf("valid signature\n");
	}
	else {
		printf("invalid signature\n");
	}

	return 0;
}
