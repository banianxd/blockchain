
#include <iostream>
#include <string>
#include <vector>
#include <iterator>

#include "BtcApi.h"
#include "uEcc/uECC.h"
#include <uEcc/macroECC.h>

#include "crypto/base58.h"
#include "crypto/utility_tools.h"
#include "crypto/hmac_sha512.h"
#include "crypto/hash.h"
#include "crypto/ripemd160.h"
#include "btc/script.h"
#include "usdt/createpayload.h"
#include "btc/segwit_addr.h"

// ===================================================================

struct TransactionInput
{
	string address;
	string previous_output_hash;
	uint32_t previous_output_index;
	string script;
	uint32_t sequence;
};

struct TransactionOutput
{
	string address;
	string script;
	uint64_t value;
};

struct TransactionBill
{
	string hash;
	uint32_t locktime;
	uint32_t version;
	vector<TransactionInput> inputs;
	vector<TransactionOutput> outputs;

	// use in segwit
	uint8_t marker;
	uint8_t flag;
	string str_witness;
};

void tx_decode(bool is_testnet, const string tx_str, TransactionBill& tb)
{
	Binary hash = bitcoin256(Binary::decode(tx_str));
	hash.reverse();
	tb.hash = Binary::encode(hash);

	size_t index = 0;
	tb.version = little_endian_to_uint32_t(tx_str.substr(index, 8));
	index += 8;

	string str_input_count = tx_str.substr(index, 2);
	size_t input_count = (size_t)(string_to_uint8_t(str_input_count));
	index += 2;
	for (size_t i = 0; i < input_count; i++)
	{
		TransactionInput in;
		in.previous_output_hash = reverse_big_little_endian(tx_str.substr(index, 64));
		index += 64;
		in.previous_output_index = little_endian_to_uint32_t(tx_str.substr(index, 8));
		index += 8;
		string str_script_len_tag = tx_str.substr(index, 2);
		index += 2;

		uint8_t script_len_tag = string_to_uint8_t(str_script_len_tag);
		if ( 0 < script_len_tag && script_len_tag < 0xfd) {
			in.script = tx_str.substr(index, script_len_tag * 2);
			index += script_len_tag * 2;
		}
		else if (script_len_tag == 0xfd) {
			string str_script_len = tx_str.substr(index, 4);
			index += 4;
			uint16_t script_len = little_endian_to_uint16_t(str_script_len);
			in.script = tx_str.substr(index, script_len * 2);
			index += script_len * 2;
		}
		else if (script_len_tag == 0xfe) {
			string str_script_len = tx_str.substr(index, 8);
			index += 8;
			uint32_t script_len = little_endian_to_uint32_t(str_script_len);
			in.script = tx_str.substr(index, script_len * 2);
			index += script_len * 2;
		}
		else if (script_len_tag == 0xff){
			string str_script_len = tx_str.substr(index, 16);
			index += 16;
			uint64_t script_len = little_endian_to_uint64_t(str_script_len);
			in.script = tx_str.substr(index, script_len * 2);
			index += script_len * 2;
		}

		in.sequence = little_endian_to_uint32_t(tx_str.substr(index, 8));
		index += 8;

		tb.inputs.push_back(in);
	}

	string str_output_count = tx_str.substr(index, 2);
	size_t output_count = (size_t)(string_to_uint8_t(str_output_count));
	index += 2;
	for (size_t i = 0; i < output_count; i++)
	{
		TransactionOutput out;
		out.value = little_endian_to_uint64_t(tx_str.substr(index, 16));
		index += 16;
		string str_pubkey_script_len = tx_str.substr(index, 2);
		index += 2;
		uint8_t u8_pubkey_script_len = string_to_uint8_t(str_pubkey_script_len);
		out.script = tx_str.substr(index, u8_pubkey_script_len * 2);
		index += u8_pubkey_script_len * 2;

		size_t pos = out.script.find("76a914");
		if (-1 != pos)
		{
			string str_pubkey_hash = out.script.substr(pos + 6, 0x14 * 2);
			if (is_testnet)
				out.address = encode_base58check(Binary::decode(str_pubkey_hash), 0x6f);
			else
				out.address = encode_base58check(Binary::decode(str_pubkey_hash), 0x00);
		}

		tb.outputs.push_back(out);
	}

	tb.locktime = little_endian_to_uint32_t(tx_str.substr(index, 8));
}

void tx_decode_segwit(bool is_testnet, const string tx_str, TransactionBill& tb)
{
	Binary hash = bitcoin256(Binary::decode(tx_str));
	hash.reverse();
	tb.hash = Binary::encode(hash);

	size_t index = 0;
	tb.version = little_endian_to_uint32_t(tx_str.substr(index, 8));
	index += 8;
	tb.marker = string_to_uint8_t(tx_str.substr(index, 2));
	index += 2;
	tb.flag = string_to_uint8_t(tx_str.substr(index, 2));
	index += 2;

	string str_input_count = tx_str.substr(index, 2);
	size_t input_count = (size_t)(string_to_uint8_t(str_input_count));
	index += 2;
	for (size_t i = 0; i < input_count; i++)
	{
		TransactionInput in;
		in.previous_output_hash = reverse_big_little_endian(tx_str.substr(index, 64));
		index += 64;
		in.previous_output_index = little_endian_to_uint32_t(tx_str.substr(index, 8));
		index += 8;
		string str_script_len_tag = tx_str.substr(index, 2);
		index += 2;

		uint8_t script_len_tag = string_to_uint8_t(str_script_len_tag);
		if (0 < script_len_tag && script_len_tag < 0xfd) {
			in.script = tx_str.substr(index, script_len_tag * 2);
			index += script_len_tag * 2;
		}
		else if (script_len_tag == 0xfd) {
			string str_script_len = tx_str.substr(index, 4);
			index += 4;
			uint16_t script_len = little_endian_to_uint16_t(str_script_len);
			in.script = tx_str.substr(index, script_len * 2);
			index += script_len * 2;
		}
		else if (script_len_tag == 0xfe) {
			string str_script_len = tx_str.substr(index, 8);
			index += 8;
			uint32_t script_len = little_endian_to_uint32_t(str_script_len);
			in.script = tx_str.substr(index, script_len * 2);
			index += script_len * 2;
		}
		else if (script_len_tag == 0xff) {
			string str_script_len = tx_str.substr(index, 16);
			index += 16;
			uint64_t script_len = little_endian_to_uint64_t(str_script_len);
			in.script = tx_str.substr(index, script_len * 2);
			index += script_len * 2;
		}

		in.sequence = little_endian_to_uint32_t(tx_str.substr(index, 8));
		index += 8;

		tb.inputs.push_back(in);
	}

	string str_output_count = tx_str.substr(index, 2);
	size_t output_count = (size_t)(string_to_uint8_t(str_output_count));
	index += 2;
	for (size_t i = 0; i < output_count; i++)
	{
		TransactionOutput out;
		out.value = little_endian_to_uint64_t(tx_str.substr(index, 16));
		index += 16;
		string str_pubkey_script_len = tx_str.substr(index, 2);
		index += 2;
		uint8_t u8_pubkey_script_len = string_to_uint8_t(str_pubkey_script_len);
		out.script = tx_str.substr(index, u8_pubkey_script_len * 2);
		index += u8_pubkey_script_len * 2;

		/*size_t pos = out.script.find("76a914");
		if (-1 != pos)
		{
			string str_pubkey_hash = out.script.substr(pos + 6, 0x14 * 2);
			if (is_testnet)
				out.address = encode_base58check(Binary::decode(str_pubkey_hash), 0x6f);
			else
				out.address = encode_base58check(Binary::decode(str_pubkey_hash), 0x00);
		}*/

		tb.outputs.push_back(out);
	}

	tb.locktime = little_endian_to_uint32_t(tx_str.substr(index, 8));
}

string tx_encode(const TransactionBill& tb)
{
	string str_version = uint32_t_to_little_endian(tb.version);
	string str_encode = str_version;

	str_encode += uint8_t_to_string((uint8_t)(tb.inputs.size()));
	for (size_t i = 0; i < tb.inputs.size(); i++)
	{
		str_encode += reverse_big_little_endian(tb.inputs[i].previous_output_hash);
		str_encode += uint32_t_to_little_endian(tb.inputs[i].previous_output_index);

		uint64_t script_len = (uint64_t)(tb.inputs[i].script.size() / 2);
		string str_tag_len = BTCAPI::get_tag_len(script_len);
		str_encode += str_tag_len;
		if (str_tag_len != "00")
			str_encode += tb.inputs[i].script;

		str_encode += uint32_t_to_little_endian(tb.inputs[i].sequence);
	}

	str_encode += uint8_t_to_string((uint8_t)(tb.outputs.size()));
	for (size_t i = 0; i < tb.outputs.size(); i++)
	{
		str_encode = str_encode + uint64_t_to_little_endian(tb.outputs[i].value);
		uint8_t u8_pubkey_script_len = (uint8_t)tb.outputs[i].script.size();
		string str_pubkey_script_len = uint8_t_to_string(u8_pubkey_script_len / 2);
		str_encode += str_pubkey_script_len;
		str_encode += tb.outputs[i].script;
	}

	if (tb.str_witness != "") {
		str_encode += tb.str_witness;
	}

	str_encode += uint32_t_to_little_endian(tb.locktime);
	return str_encode;
}

string tx_encode_segwit(const TransactionBill& tb)
{
	string str_version = uint32_t_to_little_endian(tb.version);
	string str_encode = str_version;
	str_encode += uint8_t_to_string(tb.marker);
	str_encode += uint8_t_to_string(tb.flag);

	str_encode += uint8_t_to_string((uint8_t)(tb.inputs.size()));
	for (size_t i = 0; i < tb.inputs.size(); i++)
	{
		str_encode += reverse_big_little_endian(tb.inputs[i].previous_output_hash);
		str_encode += uint32_t_to_little_endian(tb.inputs[i].previous_output_index);

		uint64_t script_len = (uint64_t)(tb.inputs[i].script.size() / 2);
		string str_tag_len = BTCAPI::get_tag_len(script_len);
		str_encode += str_tag_len;
		if (str_tag_len != "00")
			str_encode += tb.inputs[i].script;

		str_encode += uint32_t_to_little_endian(tb.inputs[i].sequence);
	}

	str_encode += uint8_t_to_string((uint8_t)(tb.outputs.size()));
	for (size_t i = 0; i < tb.outputs.size(); i++)
	{
		str_encode = str_encode + uint64_t_to_little_endian(tb.outputs[i].value);
		uint8_t u8_pubkey_script_len = (uint8_t)tb.outputs[i].script.size();
		string str_pubkey_script_len = uint8_t_to_string(u8_pubkey_script_len / 2);
		str_encode += str_pubkey_script_len;
		str_encode += tb.outputs[i].script;
	}

	if (tb.str_witness != "") {
		str_encode += tb.str_witness;
	}

	str_encode += uint32_t_to_little_endian(tb.locktime);
	return str_encode;
}

std::string witness_encode(const Witness& witness) {
	if (witness.str_pubkey_compress.size() != 66
		|| (witness.str_pubkey_compress.substr(0, 2) != "02" && witness.str_pubkey_compress.substr(0, 2) != "03")) {
		return std::string("");
	}
	if ("" == witness.str_sign) {
		return std::string("");
	}

	std::string str_witness = "02";
	str_witness = str_witness + uint8_t_to_string(uint8_t(witness.str_sign.size() / 2));
	str_witness = str_witness + witness.str_sign;
	str_witness = str_witness + uint8_t_to_string(uint8_t(witness.str_pubkey_compress.size() / 2));
	str_witness = str_witness + witness.str_pubkey_compress;
	return str_witness;
}

namespace BTCAPI
{
std::string str_sha256(const std::string& str) {
	if ("" == str) {
		return std::string("");
	}

	Binary sz_str = Binary::decode(str);
	std::string strsha256 = Binary::encode(sha256_hash(sz_str));
	return strsha256;
}

std::string str_reverse(const std::string& str) {
	if ("" == str) {
		return std::string("");
	}

	std::string str_rev = reverse_big_little_endian(str);
	return str_rev;
}

std::string decompress_pubkey(const std::string& str_pubkey_compress) {
	if ("" == str_pubkey_compress) {
		return std::string("");
	}

	const struct uECC_Curve_t * curve = uECC_secp256k1();
	Binary uPubkey(64);
	Binary pubkey = Binary::decode(str_pubkey_compress);
	uECC_decompress(pubkey.data(), uPubkey.data(), curve);
	std::string str_pubkey_uncompress = "04" + Binary::encode(uPubkey);
	return str_pubkey_uncompress;
}

std::string compress_pubkey(const std::string& str_pubkey_uncompress) {
	if (str_pubkey_uncompress.size() != 128 && str_pubkey_uncompress.size() != 130) {
		return std::string("");
	}

	std::string str_pubkey;
	if (128 == str_pubkey_uncompress.size()) {
		str_pubkey = str_pubkey_uncompress;
	}
	else if (130 == str_pubkey_uncompress.size() && str_pubkey_uncompress.substr(0, 2) == "04") {
		str_pubkey = str_pubkey_uncompress.substr(2);
	}

	Binary sz_pubkey_uncompress = Binary::decode(str_pubkey);
	Binary sz_pubkey_compress(33);
	const struct uECC_Curve_t * curve = uECC_secp256k1();
	uECC_compress(sz_pubkey_uncompress.data(), sz_pubkey_compress.data(), curve);
	std::string str_pubkey_compress = Binary::encode(sz_pubkey_compress);
	return str_pubkey_compress;
}

string get_tag_len(uint64_t u64_len) {
	if (u64_len < 0xfd) {
		return uint8_t_to_string((uint8_t)u64_len);
	}
	else if (u64_len < 0xffff) {
		return "fd" + uint16_t_to_little_endian((uint16_t)u64_len);
	}
	else if (u64_len < 0xffffffff) {
		return "fe" + uint32_t_to_little_endian((uint32_t)u64_len);
	}
	else {
		return "ff" + uint64_t_to_little_endian(u64_len);
	}
}

bool validate_address(string address)
{
	if (address.size() != 34)
		return false;
	if (address[0] != '1' && address[0] != '3' && address[0] != 'm' && address[0] != 'n')
		return false;

	Binary bin_address = decode_base58(address);
	Binary checkdata = bin_address.left(bin_address.size() - 4);
	Binary checksum_verify = bitcoin256(checkdata);

	if (checksum_verify.left(4) != bin_address.right(4))
		return false;

	return true;
}

/*
这个废弃了
// 原 ec_new，返回 private_key
string get_private_key(const string& seed)
{
	if (0 != seed.size() % 2)
		return string("");

	Binary bin_seed = Binary::decode(seed);
	Binary key("Bitcoin seed");
	Binary hash(64);
	HMACSHA512(bin_seed.data(), bin_seed.size(), key.data(), key.size(), hash.data());

	string str_hash = Binary::encode(hash);
	str_hash = str_hash.substr(0, 64);

	return str_hash;
}
*/

string get_private_key(bool is_testnet, const string& seed)
{
	if (!is_testnet)
		return bip44_get_private_key(seed, "m/44'/0'/0'/0/0");
	else
		return bip44_get_private_key(seed, "m/44'/1'/0'/0/0");
}

// 原 ec_to_public，返回 public_key
string get_public_key(const string& private_key, bool compress)
{
	string public_key;
	int compress_flag = 0;	// 0:compress, 1:uncompress

	if (!compress)
	{
		if (66 == private_key.size() && "01" == private_key.substr(private_key.size() - 2))
			compress_flag = 0;
		else if (64 == private_key.size())
			compress_flag = 1;
		else
			return public_key;	// private key error, return
	}

	Binary bin_private_key(32);
	bin_private_key = Binary::decode(private_key);

	Binary bin_public_key(64);
	const struct uECC_Curve_t * curve = uECC_secp256k1();

	if (!uECC_compute_public_key(bin_private_key.data(), bin_public_key.data(), curve))
		return public_key;

	if (0 == compress_flag)
	{
		Binary bin_public_key_compress(33);
		uECC_compress(bin_public_key.data(), bin_public_key_compress.data(), curve);
		public_key = Binary::encode(bin_public_key_compress);
	}
	else if (1 == compress_flag)
	{
		public_key = Binary::encode(bin_public_key);
	}

	return public_key;
}

// 原 ec_to_address，返回 address
string get_address(bool is_testnet, const string& public_key)
{
	// const uint8_t mainnet_p2kh = 0x00;
	// const uint8_t testnet_p2kh = 0x6f;
	uint8_t version = 0x00;
	if (is_testnet)
		version = 0x6f;

	Binary hash = bitcoin160(Binary::decode(public_key));
	return encode_base58check(hash, version);
}

string get_redeem_script(const vector<string> &vec_pubkey, uint8_t m, uint8_t n)
{
	if (n > 0x0f || m > n || n != vec_pubkey.size())
		return string("");

	m += 80;
	n += 80;
	string str_redeem_script = uint8_t_to_string(m);
	for (size_t i = 0; i < vec_pubkey.size(); ++i)
	{
		if (66 != vec_pubkey[i].size() && 130 != vec_pubkey[i].size())
			return string("");

		str_redeem_script += uint8_t_to_string((uint8_t)vec_pubkey[i].size() / 2);
		str_redeem_script += vec_pubkey[i];
	}
	str_redeem_script += uint8_t_to_string(n);
	str_redeem_script += "ae";
	return str_redeem_script;
}

string get_multisign_address(const string &str_redeem_script, bool is_testnet /* = false */)
{
	if ("" == str_redeem_script) {
		return string("");
	}

	Binary sz_redeem_script = Binary::decode(str_redeem_script);
	Binary sz_script_hash = bitcoin160(sz_redeem_script);

	uint8_t version = 0;
	if (is_testnet)
		version = 0xc4;
	else
		version = 0x05;

	return encode_base58check(sz_script_hash, version);
}

string decode_script(const string& script_str)
{
	return decode_script_(script_str);
}

string encode_script(const string& script_str)
{
	return encode_script_(script_str);
}

string tx_hash(const string& tx_str)
{
	return Binary::encode(bitcoin256(Binary::decode(tx_str)));
}

string signature(const string& str_prikey, const string& str_hash)
{
	if (str_prikey.size() != 64 || str_hash.size() != 64)
		return string("");

	Binary hash = Binary::decode(str_hash);
	Binary prikey = Binary::decode(str_prikey);
	Binary sign(64);
	int v = mECC_sign_forbc(prikey.data(), hash.data(), sign.data());
	return Binary::encode(sign);
}

// 序列化
string sig_serialize(const string& sig)
{
	Binary bin_sig = Binary::decode(sig);
	Binary ar = bin_sig.left(32);
	Binary as = bin_sig.right(32);

	Binary r, s;
	r.push_back(0);
	r += ar;
	s.push_back(0);
	s += as;

	unsigned char *rp = r.data(), *sp = s.data();
	size_t lenR = r.size(), lenS = s.size();

	while (lenR > 1 && rp[0] == 0 && rp[1] < 0x80)
	{
		lenR--; rp++;
	}
	while (lenS > 1 && sp[0] == 0 && sp[1] < 0x80)
	{
		lenS--; sp++;
	}

	Binary output;
	output.push_back(0x30);
	output.push_back((unsigned char)(4 + lenS + lenR));
	output.push_back(0x02);
	output.push_back((unsigned char)lenR);
	output += Binary(rp, lenR);
	output.push_back(0x02);
	output.push_back((unsigned char)lenS);
	output += Binary(sp, lenS);

	return Binary::encode(output);
}

string sign_input(bool is_testnet, const string& str_tx, const int input_index, const string& input_script, const string& private_key)
{
	TransactionBill tx;
	tx_decode(is_testnet, str_tx, tx);
	tx.inputs[input_index].script = input_script;

	uint32_t u32_sign_type = 1;
	string str_script_tx = tx_encode(tx) + uint32_t_to_little_endian(u32_sign_type);
	string str_hash = Binary::encode(bitcoin256(Binary::decode(str_script_tx)));
	string str_sign = signature(private_key, str_hash);
	str_sign = sig_serialize(str_sign) + "01";
	return str_sign;
}

string sign_input_segwit(bool is_testnet, const string& str_tx, const int input_index, const string& input_script, const string& private_key)
{
	TransactionBill tx;
	tx_decode_segwit(is_testnet, str_tx, tx);
	tx.inputs[input_index].script = input_script;

	uint32_t u32_sign_type = 1;
	string str_script_tx = tx_encode_segwit(tx) + uint32_t_to_little_endian(u32_sign_type);
	string str_hash = Binary::encode(bitcoin256(Binary::decode(str_script_tx)));
	string str_sign = signature(private_key, str_hash);
	str_sign = sig_serialize(str_sign) + "01";
	return str_sign;
}

void dump_tx(bool is_testnet, const string tx_str)
{
	TransactionBill tb;
	tx_decode(is_testnet, tx_str, tb);

	printf("transaction\n{\n");
	printf("\thash %s\n", tb.hash.c_str());
	printf("\tinputs\n\t{\n");

	for (size_t i = 0; i < tb.inputs.size(); i++)
	{
		printf("\t\tinput\n");
		printf("\t\t{\n");

		printf("\t\t\tprevious_output\n");
		printf("\t\t\t{\n");

		printf("\t\t\t\thash %s\n", tb.inputs[i].previous_output_hash.c_str());
		printf("\t\t\t\tindex %u\n", tb.inputs[i].previous_output_index);

		printf("\t\t\t}\n");
		// printf("\t\t\tscript %s\n", tb.inputs[i].script.c_str());
		string str_script = tb.inputs[i].script;
		string str_sign, str_pubkey;
		if ("" != str_script)
		{
			size_t script_index = 0;
			uint8_t u8_sign_len = string_to_uint8_t(str_script.substr(0, 2));
			script_index += 2;
			str_sign = str_script.substr(script_index, u8_sign_len * 2);
			script_index += u8_sign_len * 2;
			uint8_t u8_pubkey_len = string_to_uint8_t(str_script.substr(script_index, 2));
			script_index += 2;
			str_pubkey = str_script.substr(script_index, u8_pubkey_len * 2);
			script_index += u8_pubkey_len * 2;
		}			
		printf("\t\t\tscript \"[%s] [%s]\"\n", str_sign.c_str(), str_pubkey.c_str());

		printf("\t\t\tsequence %08X\n", tb.inputs[i].sequence);

		printf("\t\t}\n");
	}
	printf("\t}\n");

	printf("\tlock_time %u\n", tb.locktime);
	printf("\toutputs\n\t{\n");
	for (size_t i = 0; i < tb.outputs.size(); i++)
	{
		printf("\t\toutput\n");
		printf("\t\t{\n");
		if ("" != tb.outputs[i].address)
			printf("\t\t\taddress %s\n", tb.outputs[i].address.c_str());
		printf("\t\t\tscript \"%s\"\n", decode_script_(tb.outputs[i].script).c_str());
		printf("\t\t\tvalue %I64u\n", tb.outputs[i].value);
		printf("\t\t}\n");
	}
	printf("\t}\n");
	printf("\tversion %u\n", tb.version);

	printf("}\n");
}

/*
int tx_len(const int inputs, const int outputs)
{
	int len = 9 + inputs * 147 + outputs * 35;
	return len;
}

int firmware_tx_len(UserTransaction* ut)
{
	size_t i;
	u256 value_sum = 0;
	vector<Utxo> utxo_list;
	u256 fee = ut->fee_count * ut->fee_price;

	for (i = 0; i < ut->utxo_list.size(); i++)
	{
		value_sum += ut->utxo_list[i].value;
		if (value_sum >= (ut->pay + fee))
			break;
	}

	int o = 1;
	if (!ut->change_address.empty())
		o = 2;

	size_t len = 9 + ((i + 1) * 147) + (o * 35);
	return (int)len;
}
*/

// 采用模拟签名的方式获得交易串长度
int get_tx_len(UserTransaction* ut)
{
	UserTransaction fx;
	fx.from_address = "16TEzNLEMX5dpm18gGbzZ6X9cFoqgUPuMk";
	fx.to_address = "15KJzn2AzrL8hkyfvrGWf2qKpEyR5U8u3Z";
	fx.change_address = "16TEzNLEMX5dpm18gGbzZ6X9cFoqgUPuMk";
	fx.pay = ut->pay;
	fx.fee_count = 0;
	fx.fee_price = 0;
	fx.utxo_list = ut->utxo_list;

	int retcode = make_unsign_tx(&fx);
	if (retcode != 0)
		return(retcode);

	sign_tx(false, &fx, "2260d0236ce4bf2836aeea1fda679ac811e3c09e9e47e038d61034b1f491e75d");
	make_sign_tx(false, &fx);

	return (int)fx.tx_str.size() / 2;
}

string get_output_script(string address)
{
	string script;

	const char fc_addr = address[0];
	if ((fc_addr == '1') || (fc_addr == 'm') || (fc_addr == 'n'))
	{
		script = "76a914" + get_pubkey_hash_from_base58check(address) + "88ac";
	}
	else if ((fc_addr == '3') || (fc_addr == '2'))
	{
		script = "a914" + get_pubkey_hash_from_base58check(address) + "87";
	}
	else
		script = "";	// 不支持这种交易

	return script;
}

int make_unsign_tx(UserTransaction* ut)
{
	TransactionBill tx;
	tx.version = 1;
	tx.locktime = 0;

	u256 value_sum = 0;
	ut->input_count = 0;
	u256 fee = ut->fee_count * ut->fee_price;

	for (size_t i = 0; i < ut->utxo_list.size(); i++)
	{
		TransactionInput input;
		input.previous_output_hash = ut->utxo_list[i].hash;
		input.previous_output_index = ut->utxo_list[i].index;
		input.sequence = 0xffffffff;
		tx.inputs.push_back(input);

		// 保存每一个前交易脚本
		ut->input_count++;

		value_sum += ut->utxo_list[i].value;
		if (value_sum >= (ut->pay + fee))
			break;
	}

	if (value_sum < (ut->pay + fee))
		return -1;		// 余额不足

	TransactionOutput output0;
	output0.address = ut->to_address;
	output0.script = get_output_script(output0.address);
	if (output0.script.empty())
		return -2;		// 不支持这种交易

	output0.value = (uint64_t)(ut->pay);
	tx.outputs.push_back(output0);

	u256 change = value_sum - ut->pay - fee;
	if (!ut->change_address.empty() && (change > 500))
	{
		TransactionOutput output1;
		output1.address = ut->change_address;
		output1.script = get_output_script(output1.address);
		if (output1.script.empty())
			return -2;		// 不支持这种交易

		output1.value = (uint64_t)change;
		tx.outputs.push_back(output1);
	}

	ut->tx_str = tx_encode(tx);

	return 0;
}

// 生成固件需要的格式的数据
Binary firmware_prepare_data(bool is_testnet, UserTransaction* ut, int script_index)
{
	Binary fdata(6);

	*((int*)fdata.data()) = ut->change_wallet_index;
	fdata.data()[4] = 0;	// 收款地址在output中的序号
	fdata.data()[5] = 1;	// 找零地址在output中的序号

	TransactionBill tx;
	tx_decode(is_testnet, ut->tx_str, tx);
	tx.inputs[script_index].script = encode_script_(ut->utxo_list[script_index].script);

	string str_tx = tx_encode(tx);
	fdata += Binary::decode(str_tx);

	Binary tail(4);
	*((unsigned long*)tail.data()) = 1;	// 注意最后要补一个4字节小端序的0x01
	fdata += tail;

	return fdata;
}

void firmware_process_result(UserTransaction* ut, int index, char* result, int result_size)
{
	unsigned char len1 = result[0];
	ut->public_key = Binary(result + 1, len1);

	unsigned char len2 = result[len1 + 1];
	Binary sig = Binary(result + len1 + 2, len2);

	//ut->sig_data[index] = sig;
	ut->sig_data.push_back(sig);
}

void sign_tx(bool is_testnet, UserTransaction* ut, const string& private_key)
{
	ut->public_key = Binary::decode(get_public_key(private_key));
	ut->sig_data.clear();

	for (int i = 0; i < ut->input_count; i++)
	{
		string prev_utxo_script = encode_script_(ut->utxo_list[i].script);
		string signed_tx = sign_input(is_testnet, ut->tx_str, i, prev_utxo_script, private_key);
		ut->sig_data.push_back(Binary::decode(signed_tx));
	}
}

void multisign_tx(bool is_testnet, UserTransaction* ut, const string &private_key, const string &redeem_script)
{
	if (NULL == ut || "" == private_key || "" == redeem_script)
		return;

	//cout << "prikey:\n" << private_key << endl;
	for (int i = 0; i < ut->input_count; i++)
	{
		string sign_data;
		//cout << "redeem_script:\n" << str_redeem_script << endl;
		sign_data = sign_input(is_testnet, ut->tx_str, i, redeem_script, private_key);

		//cout << "sign_data:\n" << sign_data << endl;
		if (ut->input_sign_data.size() == i) {
			ut->input_sign_data.push_back(vector<Binary>());
		}
		ut->input_sign_data[i].push_back(Binary::decode(sign_data));
	}
}

void make_sign_tx(bool is_testnet, UserTransaction* ut)
{
	TransactionBill tx;
	tx_decode(is_testnet, ut->tx_str, tx);
	string str_pubkey = Binary::encode(ut->public_key);

	for (int i = 0; i < ut->input_count; i++)
	{
		string str_sign = Binary::encode(ut->sig_data[i]);

		string str_script;
		str_script += uint8_t_to_string((uint8_t)ut->sig_data[i].size());
		str_script += str_sign;
		str_script += uint8_t_to_string((uint8_t)ut->public_key.size());
		str_script += str_pubkey;

		tx.inputs[i].script = str_script;
	}

	ut->tx_str = tx_encode(tx);
}

void make_multisign_tx(bool is_testnet, UserTransaction* ut, const string &redeem_script)
{
	TransactionBill tx;
	tx_decode(is_testnet, ut->tx_str, tx);

	for (int i = 0; i < ut->input_count; i++)
	{
		string str_unlock_script;

		str_unlock_script += "00";		// OP_0
		string str_signs;
		for (size_t sign_count = 0; sign_count < ut->input_sign_data[i].size(); ++sign_count)
		{
			string str_sign = Binary::encode(ut->input_sign_data[i][sign_count]);
			str_signs += uint8_t_to_string((uint8_t)str_sign.size() / 2);
			str_signs += str_sign;
		}

		str_unlock_script += str_signs;
		str_unlock_script += "4c";
		str_unlock_script += get_tag_len((uint8_t)redeem_script.size() / 2);
		str_unlock_script += redeem_script;
		tx.inputs[i].script = str_unlock_script;
		//cout << "unlock script:\n" << str_unlock_script << endl;
	}
	ut->tx_str = tx_encode(tx);
}

int make_segwit_unsign_tx(UserTransaction* ut) {
	TransactionBill tx;
	tx.version = 1;
	tx.marker = 0;
	tx.flag = 1;
	tx.locktime = 0;

	u256 value_sum = 0;
	ut->input_count = 0;
	u256 fee = ut->fee_count * ut->fee_price;

	for (size_t i = 0; i < ut->utxo_list.size(); i++)
	{
		TransactionInput input;
		input.previous_output_hash = ut->utxo_list[i].hash;
		input.previous_output_index = ut->utxo_list[i].index;
		input.sequence = 0xffffffff;
		tx.inputs.push_back(input);

		// 保存每一个前交易脚本
		ut->input_count++;

		value_sum += ut->utxo_list[i].value;
		if (value_sum >= (ut->pay + fee))
			break;
	}

	if (value_sum < (ut->pay + fee))
		return -1;		// 余额不足

	TransactionOutput output0;
	output0.address = ut->to_address;
	output0.script = get_output_script(output0.address);
	if (output0.script.empty())
		return -2;		// 不支持这种交易

	output0.value = (uint64_t)(ut->pay);
	tx.outputs.push_back(output0);

	u256 change = value_sum - ut->pay - fee;
	if (!ut->change_address.empty() && (change > 500))
	{
		TransactionOutput output1;
		output1.address = ut->change_address;
		output1.script = get_output_script(output1.address);
		if (output1.script.empty())
			return -2;		// 不支持这种交易

		output1.value = (uint64_t)change;
		tx.outputs.push_back(output1);
	}

	ut->tx_str = tx_encode_segwit(tx);

	return 0;
}

std::string get_sign_hash_preimage(UserTransaction* ut, int index, const std::string& str_pubkey_compress) {
	if (NULL == ut) {
		return std::string("");
	}

	TransactionBill tx;
	tx_decode_segwit(false, ut->tx_str, tx);

	std::string str_hash_preimage = uint32_t_to_little_endian(tx.version);
	std::cout << "str_version:\n" << str_hash_preimage << std::endl;

	std::string str_prevouts;
	//for (size_t i = 0; i < tx.inputs.size(); i++) {
		// str_prevouts += tx.inputs[index].previous_output_hash;
		str_prevouts += reverse_big_little_endian(tx.inputs[index].previous_output_hash);
		str_prevouts += uint32_t_to_little_endian(tx.inputs[index].previous_output_index);
	//}
		std::cout << "str_prevouts:\n" << str_prevouts << std::endl;
	Binary sz_hash_prevouts = bitcoin256(Binary::decode(str_prevouts));
	str_hash_preimage += Binary::encode(sz_hash_prevouts);

	std::string str_sequence;
	//for (size_t i = 0; i < tx.inputs.size(); i++) {
		str_sequence += uint32_t_to_little_endian(tx.inputs[index].sequence);
	//}
	Binary sz_hash_sequence = bitcoin256(Binary::decode(str_sequence));
	str_hash_preimage += Binary::encode(sz_hash_sequence);

	//for (size_t i = 0; i < tx.inputs.size(); i++) {
		str_hash_preimage += reverse_big_little_endian(tx.inputs[index].previous_output_hash);
		str_hash_preimage += uint32_t_to_little_endian(tx.inputs[index].previous_output_index);
		std::string str_hash_pubkey = Binary::encode(bitcoin160(Binary::decode(str_pubkey_compress)));
		str_hash_pubkey = "1976a914" + str_hash_pubkey + "88ac";
		str_hash_preimage += str_hash_pubkey;

		//std::string prev_utxo_script = encode_script_(ut->utxo_list[index].script);
		//str_hash_preimage += uint8_t_to_string(uint8_t(prev_utxo_script.size() / 2));
		//str_hash_preimage += prev_utxo_script;
		str_hash_preimage += uint64_t_to_little_endian(ut->utxo_list[index].value);
		str_hash_preimage += uint32_t_to_little_endian(tx.inputs[index].sequence);
	//}

	std::string str_outputs;
	for (size_t i = 0; i < tx.outputs.size(); i++) {
		str_outputs += uint64_t_to_little_endian(tx.outputs[i].value);

		uint8_t u8_script_len = (uint8_t)tx.outputs[i].script.size();
		std::string str_script_len = uint8_t_to_string(u8_script_len / 2);
		str_outputs += str_script_len;
		str_outputs += tx.outputs[i].script;
	}
	std::cout << "str_outputs:\n" << str_outputs << std::endl;
	Binary sz_hash_outputs = bitcoin256(Binary::decode(str_outputs));
	str_hash_preimage += Binary::encode(sz_hash_outputs);

	str_hash_preimage += uint32_t_to_little_endian(tx.locktime);
	str_hash_preimage += uint32_t_to_little_endian(1);

	std::cout << "str_hash_preimage:\n" << str_hash_preimage << std::endl;
	return str_hash_preimage;
}

void segwit_sign_tx(UserTransaction* ut, const std::string& str_prikey, const std::string& str_pubkey_compress) {
	if (str_pubkey_compress.size() != 66
		|| (str_pubkey_compress.substr(0, 2) != "02" && str_pubkey_compress.substr(0, 2) != "03")) {
		return ;
	}
	if (str_prikey.size() != 64 || NULL == ut) {
		return;
	}

	//std::string str_script = get_p2wpkh_p2sh_script_of_pubkey_compress(str_pubkey_compress);
	//std::cout << "str_script:\n" << str_script << std::endl;

	for (int i = 0; i < ut->input_count; i++)
	{
		std::string str_hash_preimage = get_sign_hash_preimage(ut, i, str_pubkey_compress);
		std::string str_hash = Binary::encode(bitcoin256(Binary::decode(str_hash_preimage)));
		std::string str_sign = signature(str_prikey, str_hash);
		str_sign = sig_serialize(str_sign) + "01";

		//str_sign = sign_input_segwit(false, ut->tx_str, i, str_script, str_prikey);
		std::cout << "str_sign_data:\n" << str_sign << std::endl;
		Witness wit;
		wit.str_sign = str_sign;
		wit.str_pubkey_compress = str_pubkey_compress;
		ut->witnesses.push_back(wit);
	}
}

void make_segwit_tx(UserTransaction* ut) {
	if (NULL == ut) {
		return;
	}

	TransactionBill tx;
	tx_decode_segwit(false, ut->tx_str, tx);
	std::string str_witness;

	for (int i = 0; i < ut->input_count; i++) {
		std::string str_script = get_p2wpkh_p2sh_script_of_pubkey_compress(ut->witnesses[i].str_pubkey_compress);
		std::cout << "str_script:\n" << str_script << std::endl;
		tx.inputs[i].script = str_script;
		str_witness += witness_encode(ut->witnesses[i]);
	}
	tx.str_witness = str_witness;
	ut->tx_str = tx_encode_segwit(tx);
}

std::string bech32_addr_decode(const std::string& str_address) {
	if ("" == str_address) {
		return std::string("");
	}

	std::string str_hrp = str_address.substr(0, 2);
	std::pair<int, std::vector<uint8_t> > ret = segwit_addr::decode(str_hrp, str_address);
	int witver = ret.first;
	std::string str_witprog = Binary::encode(Binary(ret.second.data(), ret.second.size()));
	return str_witprog;
	// str_witprog = sha256(witness_script)
}

// pubkey_compress -> address begin with 3
std::string get_segwit_addr(bool is_testnet, const std::string& str_pubkey_compress) {
	if (str_pubkey_compress.size() != 66
		|| (str_pubkey_compress.substr(0, 2) != "02" && str_pubkey_compress.substr(0, 2) != "03")) {
		return std::string("");
	}

	std::string str_redeem_script = "0014" + Binary::encode(bitcoin160(Binary::decode(str_pubkey_compress)));
	std::string str_segwit_addr = get_multisign_address(str_redeem_script, is_testnet);
	return str_segwit_addr;
}

// pubkey_compress -> p2wpkh
std::string get_segwit_address_bech32_p2wpkh_pubkey(bool is_testnet, const std::string& str_pubkey_compress) {
	if (str_pubkey_compress.size() != 66
		|| (str_pubkey_compress.substr(0, 2) != "02" && str_pubkey_compress.substr(0, 2) != "03")) {
		return std::string("");
	}

	std::string str_hrp;
	if (is_testnet) {
		str_hrp = "tb";
	}
	else {
		str_hrp = "bc";
	}

	int witness_version = 0;
	Binary sz_pubkey_compress = Binary::decode(str_pubkey_compress);
	Binary witness_program = bitcoin160(sz_pubkey_compress);
	std::string str_addr = segwit_addr::encode(str_hrp, witness_version, witness_program);
	return str_addr;
}

// p2wsh
std::string get_p2wsh_script_of_pubkey_compress(const std::string& str_pubkey_compress) {
	if (str_pubkey_compress.size() != 66
		|| (str_pubkey_compress.substr(0, 2) != "02" && str_pubkey_compress.substr(0, 2) != "03")) {
		return std::string("");
	}

	std::string str_redeem_script = "21" + str_pubkey_compress + "ac";
	return str_redeem_script;
}

// p2wphk-p2sh
std::string get_p2wpkh_p2sh_script_of_pubkey_compress(const std::string& str_pubkey_compress) {
	if (str_pubkey_compress.size() != 66
		|| (str_pubkey_compress.substr(0, 2) != "02" && str_pubkey_compress.substr(0, 2) != "03")) {
		return std::string("");
	}

	std::string str_witness_script = Binary::encode(bitcoin160(Binary::decode(str_pubkey_compress)));
	str_witness_script = "160014" + str_witness_script;
	return str_witness_script;
}

// pubkey_compress -> p2wsh
std::string get_segwit_address_bech32_p2wsh_pubkey(bool is_testnet, const std::string& str_pubkey_compress) {
	if (str_pubkey_compress.size() != 66
		|| (str_pubkey_compress.substr(0, 2) != "02" && str_pubkey_compress.substr(0, 2) != "03")) {
		return std::string("");
	}

	std::string str_redeem_script = get_p2wsh_script_of_pubkey_compress(str_pubkey_compress);
	std::string str_addr = get_segwit_address_bech32_p2wsh_redeem_script(is_testnet, str_redeem_script);
	return str_addr;

	/*std::string str_hrp;
	if (is_testnet) {
		str_hrp = "tb";
	}
	else {
		str_hrp = "bc";
	}

	int witness_version = 0;
	std::string str_redeem_script = "21" + str_pubkey_compress + "ac";
	Binary redeem_script = Binary::decode(str_redeem_script);
	Binary witness_program = sha256_hash(redeem_script);
	std::string str_addr = segwit_addr::encode(str_hrp, witness_version, witness_program);
	return str_addr;*/
}

// redeem_script -> p2wsh
std::string get_segwit_address_bech32_p2wsh_redeem_script(bool is_testnet, const std::string& str_redeem_script) {
	if ("" == str_redeem_script) {
		return std::string("");
	}
	
	std::string str_hrp;
	if (is_testnet) {
		str_hrp = "tb";
	}
	else {
		str_hrp = "bc";
	}

	int witness_version = 0;
	Binary redeem_script = Binary::decode(str_redeem_script);
	Binary witness_program = sha256_hash(redeem_script);
	std::string str_addr = segwit_addr::encode(str_hrp, witness_version, witness_program);
	return str_addr;
}

std::string get_segwit_address_bip142_p2wpkh(bool is_testnet, const std::string& str_pubkey_uncompress) {
	if (str_pubkey_uncompress.size() != 130 || str_pubkey_uncompress.substr(0, 2) != "04") {
		return std::string("");
	}

	Binary pubkey = Binary::decode(str_pubkey_uncompress);
	Binary hash160 = bitcoin160(pubkey);

	std::string str_addr_ver, str_witprog_ver = "00", str_padding = "00";
	if (is_testnet) {
		str_addr_ver = "03";
	}
	else {
		str_addr_ver = "06";
	}

	Binary checkdata = Binary::decode(str_addr_ver + str_witprog_ver + str_padding) + hash160;
	Binary checksum = bitcoin256(checkdata).left(4);
	std::string str_addr = encode_base58(checkdata + checksum);
	return str_addr;
}

std::string get_segwit_address_bip142_p2wsh(bool is_testnet, const std::string& str_redeem_script) {
	if ("" == str_redeem_script) {
		return std::string("");
	}

	Binary redeem_script = Binary::decode(str_redeem_script);
	Binary sz_sha256 = sha256_hash(redeem_script);

	std::string str_addr_ver, str_witprog_ver = "00", str_padding = "00";
	if (is_testnet) {
		str_addr_ver = "28";
	}
	else {
		str_addr_ver = "0a";
	}

	Binary checkdata = Binary::decode(str_addr_ver + str_witprog_ver + str_padding) + sz_sha256;
	Binary checksum = bitcoin256(checkdata).left(4);
	std::string str_addr = encode_base58(checkdata + checksum);
	return str_addr;
}

}

// ===================================================================

namespace USDTAPI
{

int make_unsign_tx(UserTransaction* ut)
{
	const uint32_t omni_property_id = 31;
	TransactionBill tx;
	tx.version = 1;
	tx.locktime = 0;

	u256 value_sum = 0;
	ut->input_count = 0;
	u256 fee = ut->fee_count * ut->fee_price;

	for (size_t i = 0; i < ut->utxo_list.size(); i++)
	{
		TransactionInput input;
		input.previous_output_hash = ut->utxo_list[i].hash;
		input.previous_output_index = ut->utxo_list[i].index;
		input.sequence = 0xffffffff;
		tx.inputs.push_back(input);

		// 保存每一个前交易脚本
		ut->input_count++;

		value_sum += ut->utxo_list[i].value;
		if (value_sum >= ((u256)546 + fee))
			break;
	}

	if (value_sum < ((u256)546 + fee))
		return -1;		// 余额不足

	// 第一个压入 payload
	TransactionOutput payload;
	payload.value = 0;
	payload.script = "6a";    // 6a is op_return
	string str_payload = CreatePayload_SimpleSend(omni_property_id, (uint64_t)(ut->pay));
	string str_USDT_data = "6f6d6e69" + str_payload;
	payload.script += uint8_t_to_string((uint8_t)str_USDT_data.size() / 2);
	payload.script += str_USDT_data;
	tx.outputs.push_back(payload);

	TransactionOutput output0;
	output0.address = ut->to_address;
	output0.script = "76a914" + get_pubkey_hash_from_base58check(output0.address) + "88ac";
	output0.value = 546;
	tx.outputs.push_back(output0);

	u256 change = value_sum - 546 - fee;
	if (!ut->change_address.empty() && (change > 500))
	{
		TransactionOutput output1;
		output1.address = ut->change_address;
		output1.script = "76a914" + get_pubkey_hash_from_base58check(output1.address) + "88ac";
		output1.value = (uint64_t)change;
		tx.outputs.push_back(output1);
	}

	ut->tx_str = tx_encode(tx);

	return 0;
}

// 生成固件需要的格式的数据
Binary firmware_prepare_data(bool is_testnet, UserTransaction* ut, int script_index)
{
	Binary fdata(6);

	*((int*)fdata.data()) = ut->change_wallet_index;
	fdata.data()[4] = 1;	// 收款地址在output中的序号
	fdata.data()[5] = 2;	// 找零地址在output中的序号

	TransactionBill tx;
	tx_decode(is_testnet, ut->tx_str, tx);
	tx.inputs[script_index].script = encode_script_(ut->utxo_list[script_index].script);

	string str_tx = tx_encode(tx);
	fdata += Binary::decode(str_tx);

	Binary tail(4);
	*((unsigned long*)tail.data()) = 1;	// 注意最后要补一个4字节小端序的0x01
	fdata += tail;

	return fdata;
}

// 采用模拟签名的方式获得交易串长度
int get_tx_len(UserTransaction* ut)
{
	UserTransaction fx;
	fx.from_address = "16TEzNLEMX5dpm18gGbzZ6X9cFoqgUPuMk";
	fx.to_address = "15KJzn2AzrL8hkyfvrGWf2qKpEyR5U8u3Z";
	fx.change_address = "16TEzNLEMX5dpm18gGbzZ6X9cFoqgUPuMk";
	fx.pay = ut->pay;
	fx.fee_count = 0;
	fx.fee_price = 0;
	fx.utxo_list = ut->utxo_list;

	int retcode = make_unsign_tx(&fx);
	if (retcode != 0)
		return(retcode);

	BTCAPI::sign_tx(false, &fx, "2260d0236ce4bf2836aeea1fda679ac811e3c09e9e47e038d61034b1f491e75d");
	BTCAPI::make_sign_tx(false, &fx);

	return (int)fx.tx_str.size() / 2;
}

u256 get_usdt_from_tx(bool is_testnet, const string str_tx)
{
	TransactionBill tx;
	tx_decode(is_testnet, str_tx, tx);

	string str_usdt_amount;
	for (size_t i = 0; i < tx.outputs.size(); i++)
	{
		size_t pos = tx.outputs[i].script.find("6f6d6e69");
		if (-1 != pos)
		{
			str_usdt_amount = tx.outputs[i].script.substr(tx.outputs[i].script.size() - 16);
			uint64_t u64_usdt_amount = big_endian_to_uint64_t(str_usdt_amount);
			return (u256)u64_usdt_amount;
		}
	}
	return((u256)-1);
}

}
