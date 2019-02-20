#ifndef BTCBASE_H_
#define BTCBASE_H_

#include "TokenCommon.h"
#include <string>
#include <vector>

namespace BTCAPI
{
	string str_reverse(const std::string &str);
	std::string get_tag_len(uint64_t u64_len);

	bool validate_address(string address);										// 验证 BTC 地址的有效性
	string get_private_key(bool is_testnet, const string& seed);				// 从种子生成私钥
	string get_public_key(const string& private_key, bool compress = true);		// 从私钥生成公钥
	string get_address(bool is_testnet, const string& public_key);				// 转换公钥为收付款地址

	string get_redeem_script(const std::vector<std::string> &vec_pubkey,
		uint8_t m,	// m,n分别为m-of-n中的m,n
		uint8_t n);
	string get_multisign_address(const std::string &str_redeem_script, bool is_testnet = false);
	int make_unsign_tx_redeem(UserTransaction* ut, const std::string &str_redeem_script);
	void sign_tx_redeem(bool is_testnet, UserTransaction* ut,
		const string &private_key, const std::string &str_redeem_script);
	void make_multisign_tx(bool is_testnet, UserTransaction* ut,
		const std::string &str_redeem_script);

	string tx_hash(const string& tx_str);										// 获取交易串 hash
	void dump_tx(bool is_testnet, const string tx_str);							// 输出tx的解析结果

	int make_unsign_tx(UserTransaction* ut);
	Binary firmware_prepare_data(bool is_testnet, UserTransaction* ut, int script_index);
	void firmware_process_result(UserTransaction* ut, int index, char* result, int result_size);
	void sign_tx(bool is_testnet, UserTransaction* ut, const string &private_key);
	void make_sign_tx(bool is_testnet, UserTransaction* ut);

	string decode_script(const string& script_str);								// 解码脚本
	string encode_script(const string& script_str);								// 编码脚本
	int get_tx_len(UserTransaction* ut);										// 采用模拟签名的方式获得交易串长度(必须已获取UTXO)
}

namespace USDTAPI
{
	int make_unsign_tx(UserTransaction* ut);
	Binary firmware_prepare_data(bool is_testnet, UserTransaction* ut, int script_index);
	int get_tx_len(UserTransaction* ut);										// 采用模拟签名的方式获得交易串长度(必须已获取UTXO)
	u256 get_usdt_from_tx(bool is_testnet, const string str_tx);				// 从一个交易串里面获得usdt转账金额
}

#endif // BTCBASE_H_

