#include <BtcApi.h>

#include "Coin.h"
#include "HttpAPI\BtxonAPI.h"
#include "CosExt.h"

// 验证钱包地址是否有效
static void test_validate_address()
{
	{
		bool ret = BTCAPI::validate_address("1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E");
		VF("validate_address", ret);
	}

	{
		bool ret = BTCAPI::validate_address("mzGP6r6MUcwdocow6JnCxmxwrctKQqSL84");
		VF("validate_address", ret);
	}
}

static void test_get_private_key()
{
	{
		string private_key = BTCAPI::get_private_key(false, "37f63c464ed1e319103598012d13b5f48f4712fdd55766390eeb58f3812d71ef3da4d5eec187b80bc3896d95e3e7aaead526bedd999c3dd74ba0b137a9b194ae");
		VF("get_private_key", (private_key == "294fed288cf10b6cff57e855765759114b9603f9f235a916c939239e97b06d77"));
	}

	{
		string private_key = BTCAPI::get_private_key(true, "37f63c464ed1e319103598012d13b5f48f4712fdd55766390eeb58f3812d71ef3da4d5eec187b80bc3896d95e3e7aaead526bedd999c3dd74ba0b137a9b194ae");
		VF("get_private_key", (private_key == "9572e9246fd94cd9545e36a4bab9429477e77e1a21c0922e251fdbcd20021f8e"));
	}
}

static void test_get_public_key()
{
	{
		string public_key = BTCAPI::get_public_key("8ed1d17dabce1fccbbe5e9bf008b318334e5bcc78eb9e7c1ea850b7eb0ddb9c8");
		VF("get_public_key", (public_key == "0247140d2811498679fe9a0467a75ac7aa581476c102d27377bc0232635af8ad36"));
	}

	{
		string public_key = BTCAPI::get_public_key("8ed1d17dabce1fccbbe5e9bf008b318334e5bcc78eb9e7c1ea850b7eb0ddb9c801");
		VF("get_public_key", (public_key == "0247140d2811498679fe9a0467a75ac7aa581476c102d27377bc0232635af8ad36"));
	}

	{
		string public_key = BTCAPI::get_public_key("e50645d5eb93f456fd92502a891ba4fb199ba1e5c313b43e1eedca349905fd1701");	// 安康的
		VF("get_public_key", (public_key == "037eefdac5b0529fe7193bccaea2202ec8f2f3ad4856f213309d67276ef1392a1a"));
	}
}

static void test_get_address()
{
	{
		string address = BTCAPI::get_address(true, "0247140d2811498679fe9a0467a75ac7aa581476c102d27377bc0232635af8ad36");
		VF("get_address", (address == "mtqFYNDizo282Y29kjwXEf2dCkfdZZydbf"));
	}

	{
		string address = BTCAPI::get_address(false, "0247140d2811498679fe9a0467a75ac7aa581476c102d27377bc0232635af8ad36");
		VF("get_address", (address == "1EKJFK8kBmasFRYY3Ay9QjpJLm4vemJtC1"));
	}

	{
		string address3 = BTCAPI::get_address(true, "0447140d2811498679fe9a0467a75ac7aa581476c102d27377bc0232635af8ad36e87bb04f401be3b770a0f3e2267a6c3b14a3074f6b5ce4419f1fcdc1ca4b1cb6");
		VF("get_address", (address3 == "modCdv4bPiVHWRhJPLRxdfKuzjxz275cah"));
	}

	{
		string address = BTCAPI::get_address(false, "0447140d2811498679fe9a0467a75ac7aa581476c102d27377bc0232635af8ad36e87bb04f401be3b770a0f3e2267a6c3b14a3074f6b5ce4419f1fcdc1ca4b1cb6");
		VF("get_address", (address == "197FLrycah42jKDgfmTaok7b8kNHA7R2ih"));
	}
}

static void test_decode_script()
{
	string script = BTCAPI::decode_script("76a914d073c96316d066e5ea65c23dcd4ebaf6126ce9fb88ac");
	VF("decode_script", (script == "dup hash160 [d073c96316d066e5ea65c23dcd4ebaf6126ce9fb] equalverify checksig"));
}

// BTC 硬件签名的交易过程
static void test_firmware_sign()
{
	UserTransaction ut;
	ut.from_address = "mg9cmEEV7GB7NfsXPqc9yUvUjYH9EMUsuP";
	ut.to_address = "mjqGHq79osmPUsTHeREtUx3egEa7z3o7Yo";
	ut.change_address = "mg9cmEEV7GB7NfsXPqc9yUvUjYH9EMUsuP";
	ut.pay = gCoin["tBTC"].from_display("0.2");

	CoinType coinType = gCoin["tBTC"].type;
	BtxonAPI api;
	int ret;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret)
	{
		printf("取余额失败\n");
		return;
	}
	if (balance < ut.pay)
	{
		printf("余额不足\n");
		return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret)
	{
		printf("取UTXO失败\n");
		return;
	}

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret)
	{
		printf("取交易费失败\n");
		return;
	}

	ut.fee_count = BTCAPI::get_tx_len(&ut);
	ut.fee_price = (u256)info.midFee;
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	// 硬件签名 ==========================================
	Cos cos;
	SW sw;

	if (cos.find() <= 0)
		return;

	if (!cos.connect(0))
		return;

	if (!cos.open_channel())
		return;

	if (verify_pin(cos) != 0)
		return;

	ret = BTCAPI::make_unsign_tx(&ut);

	int result_size;
	char result[4096];

	for (int i = 0; i < ut.input_count; i++)
	{
		Binary fdata = BTCAPI::firmware_prepare_data(coinType.is_testnet(), &ut, i);
		printf("firmware_data%d:\n", i);
		binout(fdata.data(), fdata.size());
		printf("firmware_size%d:%d\n", i, (int)fdata.size());

		sw = cos.sign_transaction(coinType.major, coinType.minor, coinType.chain_id, 0, fdata.data(), fdata.size(), result, result_size);
		if (sw == SW_9000_SUCCESS)
		{
			BTCAPI::firmware_process_result(&ut, i, result, result_size);
			continue;
		}
		if (sw != SW_6D82_GET_INTERACTION_LATER)
		{
			printf("签名失败:%04x\n", sw);
			return;
		}

		char buffer[1024];
		printf("输入验证码:");
		scanf_s("%s", buffer, 1024);

		sw = cos.sign_transaction_end(buffer, result, result_size);
		if (sw != SW_9000_SUCCESS)
		{
			printf("验证失败\n");
			return;
		}

		BTCAPI::firmware_process_result(&ut, i, result, result_size);
	}

	BTCAPI::make_sign_tx(coinType.is_testnet(), &ut);
	//BTCAPI::dump_tx(true, ut->tx_str);
	printf("%s\n", ut.tx_str.c_str());
}

// BTC 软件签名的交易过程测试
static void test_sign()
{
	UserTransaction ut;
	ut.from_address = "mg9cmEEV7GB7NfsXPqc9yUvUjYH9EMUsuP";
	ut.to_address = "mjqGHq79osmPUsTHeREtUx3egEa7z3o7Yo";
	ut.change_address = "mg9cmEEV7GB7NfsXPqc9yUvUjYH9EMUsuP";

	CoinType coinType = gCoin["tBTC"].type;
	BtxonAPI api;
	int ret;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret)
	{
		printf("取余额失败\n");
		return;
	}
	if (balance < ut.pay)
	{
		printf("余额不足\n");
		return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret)
	{
		printf("取UTXO失败\n");
		return;
	}

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret)
	{
		printf("取交易费失败\n");
		return;
	}

	ut.pay = gCoin["tBTC"].from_display("0.2");
	ut.fee_count = BTCAPI::get_tx_len(&ut);
	ut.fee_price = (u256)info.midFee;
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	// 软件签名 ==========================================
	ret = BTCAPI::make_unsign_tx(&ut);
	if (ret != 0)
		return;
	BTCAPI::sign_tx(coinType.is_testnet(), &ut, "09cebf09bdb895dfe3820ba35812bbb5be2472f6291f1a965cd0144c8ae0a453");
	BTCAPI::make_sign_tx(coinType.is_testnet(), &ut);

	printf("%s\n", ut.tx_str.c_str());
}

class Wallet
{
public:
	string private_key;
	string public_key;
	string address;

	Wallet() {}
	Wallet(const string private_key)
	{
		this->private_key = private_key;
		this->public_key = BTCAPI::get_public_key(private_key);
		this->address = BTCAPI::get_address(true, this->public_key);
	}

	void set_address(const string address)
	{
		this->address = address;
	}
};

void GetWalletBalance()
{
	vector<Wallet> wallet =
	{
		Wallet("07d92015577b1ff298a7f6530c1e733f75b6c717d0e14e9f9dc04c0f9cd3a8a1"),
		Wallet("6f37c7b514f7deac821fd33c591a89c28830d11929f282ca0ecb92ae335aae5b"),
		Wallet("2260d0236ce4bf2836aeea1fda679ac811e3c09e9e47e038d61034b1f491e75d"),
		Wallet("98d01965d5e1221a38db0912bf041d0c900a5fc002054d0b7dda210522e99c90"),	//张扬的硬件
	};

	/*
	我的钱包:
	wallet address: mjqGHq79osmPUsTHeREtUx3egEa7z3o7Yo 0.360979
	wallet address: mj7n7pgZppGFgDaoRHYLVuj4XAHUySCgqw 0.068870
	wallet address: mkyCHRRDAYWtbsUkPqaNP1jUUFQYdYJwHy 0.110000
	wallet address: mzGP6r6MUcwdocow6JnCxmxwrctKQqSL84 0.464730		(模拟器钱包)
	*/
	// 16Lk8o4uwCXYVnhancmbDSCAuVTQpE238x

	BtxonAPI api;
	u256 balance, forze;
	for (int i = 0; i < wallet.size(); i++)
	{
		api.fetchBalance(gCoin["tBTC"].type, wallet[i].address, balance, forze);
		printf("wallet address: %s (%s, %s)\n", wallet[i].address.c_str(), gCoin["tBTC"].to_display(balance).toStdString().c_str(), gCoin["BTC"].to_display(forze).toStdString().c_str());
	}

	Wallet fw_wallet;
	fw_wallet.set_address("muMCrdMHhtW21wUKfqBg8zWPSJV6eG9tjT");
	api.fetchBalance(gCoin["tBTC"].type, fw_wallet.address, balance, forze);
	printf("wallet address: %s (%s, %s)\n", fw_wallet.address.c_str(), gCoin["tBTC"].to_display(balance).toStdString().c_str(), gCoin["BTC"].to_display(forze).toStdString().c_str());

	// 15KJzn2AzrL8hkyfvrGWf2qKpEyR5U8u3Z
}

// USDT 软件签名的交易过程测试
void test_usdt_sign()
{
	UserTransaction ut;
	ut.from_address = "1DBPJJoRSarbjTeNmAUxwmRPYP6vEQgztD";
	ut.to_address = "16Lk8o4uwCXYVnhancmbDSCAuVTQpE238x";
	ut.change_address = "1DBPJJoRSarbjTeNmAUxwmRPYP6vEQgztD";
	ut.pay = (uint64_t)gCoin["USDT"].from_display("5.0");
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	CoinType coinType = gCoin["USDT"].type;
	BtxonAPI api;
	int ret;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret)
	{
		printf("取余额失败\n");
		return;
	}
	if (balance < ut.pay)
	{
		printf("余额不足\n");
		return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret || ut.utxo_list.size() == 0)
	{
		printf("取UTXO失败\n");
		return;
	}

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret)
	{
		printf("取交易费失败\n");
		return;
	}

	ut.pay = 546;	// 这个仅仅是用于计算交易长度时使用(BTC)
	ut.fee_count = USDTAPI::get_tx_len(&ut);
	ut.fee_price = (u256)info.midFee;
	ut.pay = (uint64_t)gCoin["USDT"].from_display("5.0");	// 恢复真正的交易值

	// 软件签名 ==========================================
	ret = USDTAPI::make_unsign_tx(&ut);
	if (ret != 0)
		return;
	BTCAPI::sign_tx(false, &ut, "8cde367ccbe92cc7c05dde05603ca416935919eb0276ce0eb307870942d92e00");
	BTCAPI::make_sign_tx(false, &ut);

	printf("%s\n", ut.tx_str.c_str());

	u256 value = USDTAPI::get_usdt_from_tx(false, ut.tx_str);
	printf("%s\n", value.str().c_str());
}

// sp
static void sp_test_sign()
{
	string seed = mnemonic_to_seed("manual shoot jelly view scrub head also price cliff upset honey farm daring among route cheese evidence caution joy lock asset occur catalog high", "");	// 小蝶
	//string seed = mnemonic_to_seed("blue submit hurt base spray learn permit two absurd brown large extend awkward cool hair resist quarter fever brave sight palm argue adapt slush", "");	// 张扬
	string private_key = BTCAPI::get_private_key(false, seed);
	string public_key = BTCAPI::get_public_key(private_key);
	string address = BTCAPI::get_address(false, public_key);	// 1K2VpuurN1seRUvCUHj6DLGiFWASJifZ7y

	UserTransaction ut;
	ut.from_address = address;
	ut.to_address = "19uvdbPW1A2hDaNysFRB6xJDCEG5opAJg6";
	ut.change_address = address;
	//ut.pay = 15591;
	ut.pay = 10000;

	CoinType coinType = gCoin["BTC"].type;
	BtxonAPI api;
	int ret;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret)
	{
		printf("取余额失败\n");
		return;
	}
	if (balance < ut.pay)
	{
		printf("余额不足\n");
		return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret)
	{
		printf("取UTXO失败\n");
		return;
	}

	/*
	printf("points\n{\n");
	for (int i = 0; i < ut.utxo_list.size(); i++)
	{
		printf("\tpoint\n");
		printf("\t{\n");
		printf("\t\thash %s\n", ut.utxo_list[i].hash.c_str());
		printf("\t\tindex %u\n", ut.utxo_list[i].index);
		printf("\t\tvalue %I64u\n", ut.utxo_list[i].value);
		printf("\t\tscript %s\n", ut.utxo_list[i].script.c_str());
		printf("\t}\n");
	}
	printf("}\n");
	*/

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret)
	{
		printf("取交易费失败\n");
		return;
	}

	ut.fee_count = BTCAPI::get_tx_len(&ut);
	ut.fee_price = (u256)info.midFee;
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	//ut.pay = balance - (ut.fee_count*ut.fee_price);

	// 软件签名 ==========================================
	ret = BTCAPI::make_unsign_tx(&ut);
	if (ret != 0)
		return;
	BTCAPI::sign_tx(coinType.is_testnet(), &ut, private_key);
	BTCAPI::make_sign_tx(coinType.is_testnet(), &ut);

	printf("%s\n", ut.tx_str.c_str());
}

static void test_get_multisign_address()
{
	std::string str_pubkey1 = "02d7383b18a3d62fb0ef02e27770638ae05d29b87a6986f00ebb968fe1a04616fe";
	std::string str_pubkey2 = "022592d7c6bb03eb371e8e667241a8a157e8390af9d61be9856a770f3b0b3c5877";
	std::string str_pubkey3 = "036966acf2e64741b87a8ef2e26636a5b63b180d25385ccb9620589cac63e4b285";

	std::vector<std::string> vec_pubkey;
	vec_pubkey.push_back(str_pubkey1);
	vec_pubkey.push_back(str_pubkey2);
	vec_pubkey.push_back(str_pubkey3);
	std::string str_redeem_script = BTCAPI::get_redeem_script(vec_pubkey, 2, 3);
	VF("get_multisign_script", (str_redeem_script == "522102d7383b18a3d62fb0ef02e27770638ae05d29b87a6986f00ebb968fe1a04616fe21022592d7c6bb03eb371e8e667241a8a157e8390af9d61be9856a770f3b0b3c587721036966acf2e64741b87a8ef2e26636a5b63b180d25385ccb9620589cac63e4b28553ae"));

	str_redeem_script = "0014ab68025513c3dbd2f7b92a94e0581f5d50f654e7";
	string mutli_address = BTCAPI::get_multisign_address(str_redeem_script, false);
	printf("mutli_address:\n%s\n", mutli_address.c_str());
	VF("get_multisign_address", (mutli_address == "35N8Ltzqs78xyhKrNbuxNpVaxp21mgCMbb"));
}

static void test_multisign_tx()
{
	// 多签地址向普通地址转账
	string str_address = "35N8Ltzqs78xyhKrNbuxNpVaxp21mgCMbb";
	string str_prikey1 = "e2d742495a1de33e2c9d4a9b01cbea1e94f022482344146bee00ec2082634867";
	string str_prikey2 = "3d3bb0eb4ee391ee43caf59ed9635adc3a26d6edc438f2c1071d3698173e37ec";

	string str_pubkey1 = "02d7383b18a3d62fb0ef02e27770638ae05d29b87a6986f00ebb968fe1a04616fe";
	string str_pubkey2 = "022592d7c6bb03eb371e8e667241a8a157e8390af9d61be9856a770f3b0b3c5877";
	string str_pubkey3 = "036966acf2e64741b87a8ef2e26636a5b63b180d25385ccb9620589cac63e4b285";

	std::vector<std::string> vec_pubkey;
	vec_pubkey.push_back(str_pubkey1);
	vec_pubkey.push_back(str_pubkey2);
	vec_pubkey.push_back(str_pubkey3);
	std::string str_redeem_script = BTCAPI::get_redeem_script(vec_pubkey, 2, 3);

	UserTransaction ut;
	ut.from_address = "35N8Ltzqs78xyhKrNbuxNpVaxp21mgCMbb";
	ut.to_address = "1DBPJJoRSarbjTeNmAUxwmRPYP6vEQgztD";
	ut.change_address = "35N8Ltzqs78xyhKrNbuxNpVaxp21mgCMbb";

	CoinType coinType = gCoin["BTC"].type;
	BtxonAPI api;
	int ret = 0;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret) {
		printf("取余额失败\n");
		return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret) {
		printf("取UTXO失败\n");
		return;
	}

	printf("%s\n", ut.utxo_list[0].script.c_str());

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret) {
		printf("取交易费失败\n");
		return;
	}

	ut.pay = gCoin["BTC"].from_display("0.00005");
	ut.fee_count = 1;
	ut.fee_price = 4000;
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	ret = BTCAPI::make_unsign_tx(&ut);
	if (ret != 0) {
		return;
	}		
	printf("unsign tx:\n%s\n", ut.tx_str.c_str());

	BTCAPI::multisign_tx(coinType.is_testnet(), &ut, str_prikey1, str_redeem_script);
	BTCAPI::multisign_tx(coinType.is_testnet(), &ut, str_prikey2, str_redeem_script);
	BTCAPI::make_multisign_tx(coinType.is_testnet(), &ut, str_redeem_script);
	printf("sign_tx\n%s\n", ut.tx_str.c_str());
}

static void test_sign1()
{
	UserTransaction ut;
	ut.from_address = "1DBPJJoRSarbjTeNmAUxwmRPYP6vEQgztD";
	ut.to_address = "35N8Ltzqs78xyhKrNbuxNpVaxp21mgCMbb";
	//ut.change_address = "1DBPJJoRSarbjTeNmAUxwmRPYP6vEQgztD";
	ut.pay = 546;

	CoinType coinType = gCoin["BTC"].type;
	BtxonAPI api;
	int ret = 0;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret != 0) {
		printf("取余额失败\n");
		return;
	} 
	if (balance < ut.pay) {
		printf("余额不足\n");
		return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret != 0) {
		printf("取UTXO失败\n");
		return;
	}

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret != 0) {
		printf("取交易费失败\n");
		return;
	}

	//ut.pay = gCoin["tBTC"].from_display("0.2");
	//ut.fee_count = BTCAPI::get_tx_len(&ut);
	//ut.fee_price = (u256)info.midFee;
	ut.fee_count = 1;
	ut.fee_price = 2850;
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	// 软件签名 ==========================================
	ret = BTCAPI::make_unsign_tx(&ut);
	if (ret != 0) {
		return;
	}
	BTCAPI::sign_tx(coinType.is_testnet(), &ut, "8cde367ccbe92cc7c05dde05603ca416935919eb0276ce0eb307870942d92e00");
	BTCAPI::make_sign_tx(coinType.is_testnet(), &ut);
	printf("sign_tx\n%s\n", ut.tx_str.c_str());
}


static void test_get_segwit_addr() {
	// 020bc344ed703127d434a9e1bf078f8cff30c79042a24b84d64fc08370766ac9b9
	std::string str_pubkey_compress = "03931abec2a46ae5b12e2de2245c965a25e77b21a1729e5e530383bff28bca56ca";
	std::string str_segwit_addr = BTCAPI::get_segwit_addr(false, str_pubkey_compress);
	// 3DVe9HS567Z33Hnq2VzEFhwzAAAkb7VMXR
	// 34Z7bgcZoWu8YMPnuFAM1oG68jrrpy1UQR
	printf("segwit addr:\n%s\n", str_segwit_addr.c_str());
}

static void test_segarated_witness_bech32_p2wpkh_pubkey() {
	std::string str_pubkey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	std::string str_addr, str_addr_test;

	str_addr = BTCAPI::get_segwit_address_bech32_p2wpkh_pubkey(false, str_pubkey);
	// bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
	printf("Mainnet P2WPKH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_segwit_address_bech32_p2wpkh_pubkey(true, str_pubkey);
	// tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
	printf("Testnet P2WPKH:\n%s\n", str_addr_test.c_str());
}

static void test_segwit_address_bech32_p2wsh_pubkey() {
	std::string str_pubkey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	std::string str_addr, str_addr_test;
	str_addr = BTCAPI::get_segwit_address_bech32_p2wsh_pubkey(false, str_pubkey);
	// bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
	printf("Mainnet P2WSH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_segwit_address_bech32_p2wsh_pubkey(true, str_pubkey);
	// tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7
	printf("Testnet P2WSH:\n%s\n", str_addr_test.c_str());
}

static void test_segwit_address_bech32_p2wsh_redeem_script() {
	std::string str_redeem_script = "52210381a90d32c91e44434bd56dd564c4b57c70c64aa42a9eab187bddef570057eed82103ae4bf3955f2ada64671610dc4ef912da53de9af5fbc037d33e92c28a68ca43c22103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae";
	std::string str_addr, str_addr_test;
	str_addr = BTCAPI::get_segwit_address_bech32_p2wsh_redeem_script(false, str_redeem_script);
	// bc1q3tmym7hjvhu888l8ljy37yywx02zl9j3cyw6qaee5cf2cvl30e8sre8n0u
	printf("Mainnet P2WSH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_segwit_address_bech32_p2wsh_redeem_script(true, str_redeem_script);
	printf("Testnet P2WSH:\n%s\n", str_addr_test.c_str());
}

static void test_segarated_witness_bip142_p2wpkh() {
	std::string txid = "453a130a09f605b1aeca0eac8cc9607ac673f5335c7209998b36a7873252c97f";
	std::string txidrev = BTCAPI::str_reverse(txid);

	std::string str_pubkey = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	std::string str_addr, str_addr_test;

	str_addr = BTCAPI::get_segwit_address_bip142_p2wpkh(false, str_pubkey);
	// p2xtZoXeX5X8BP8JfFhQK2nD3emtjch7UeFm
	printf("Mainnet P2WPKH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_segwit_address_bip142_p2wpkh(true, str_pubkey);
	printf("Testnet P2WPKH:\n%s\n", str_addr_test.c_str());

	str_addr = BTCAPI::get_address(false, str_pubkey);
	// 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM
	printf("Mainnet P2PKH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_address(true, str_pubkey);
	printf("Testnet P2PKH:\n%s\n", str_addr_test.c_str());
}

static void get_segwit_addr() {
	std::string str_prikey = "23ea99399991e9153ab1cb3d0edf81c411aaa80686f94474e8ada8a0a7308ae9";
	std::string str_pubkey_compress = BTCAPI::get_public_key(str_prikey, true);
	printf("str_pubkey_compress:\n%s\n", str_pubkey_compress.c_str());
	std::string str_pubkey_uncompress = BTCAPI::get_public_key(str_prikey, false);
	printf("str_pubkey_uncompress:\n%s\n", str_pubkey_uncompress.c_str());

	//str_pubkey_compress = "030d519125d361437921cec4a5f672fb9d1053dfcc91b2fe3208c3378008614054";
	std::string str_segwit_addr = BTCAPI::get_segwit_addr(false, str_pubkey_compress);
	printf("str_segwit_addr:\n%s\n", str_segwit_addr.c_str());
}

static void test_segwit_tx() {
	std::string str_prikey = "30b430b434ad801cd561fd57c9b083dc3ebe787250e27c367b6599a1a57654f9";
	std::string str_pubkey_compress = "02b7be4fc0883a84e65bd33a2e528a32c409883c937285c07d2a2dbc3793e75563";
	std::string str_addr_from = "3KSgNuGVdF73seRMM8mRMPcbUb9SQmJTfy";
	std::string str_addr_to = "1PGZzja33nSCEQdNq4fc44FUkrL1uGMaUA";

	UserTransaction ut;
	ut.from_address = str_addr_from;
	ut.to_address = str_addr_to;
	//ut.change_address = str_addr_from;
	ut.pay = 3000;

	CoinType coinType = gCoin["BTC"].type;
	BtxonAPI api;
	int ret;

	// 取余额
	u256 balance, froze;
	ret = api.fetchBalanceV2(coinType, ut.from_address, true, balance, froze);
	if (ret) {
		printf("取余额失败\n");
		//return;
	}
	if (balance < ut.pay) {
		printf("余额不足\n");
		//return;
	}

	// 取 UTXO
	ret = api.getUTXO(coinType, ut.from_address, ut.utxo_list);
	if (ret) {
		printf("取UTXO失败\n");
		//return;
	}

	// 取交易费
	FeeInfo info;
	ret = api.fetchFee(coinType, info);
	if (ret) {
		printf("取交易费失败\n");
		//return;
	}

	//ut.pay = gCoin["BTC"].from_display("0.2");
	ut.fee_count = 1;
	ut.fee_price = 3000;
	ut.from_wallet_index = 0;
	ut.change_wallet_index = 0;

	// 软件签名 ==========================================
	ret = BTCAPI::make_segwit_unsign_tx(&ut);
	if (ret != 0)
		return;
	printf("unsign_tx:\n%s\n", ut.tx_str.c_str());

	BTCAPI::segwit_sign_tx(&ut, str_prikey, str_pubkey_compress);
	BTCAPI::make_segwit_tx(&ut);
	printf("sign_tx:\n%s\n", ut.tx_str.c_str());
}

static void compress_convert() {
	std::string txid = "7d51703932544cf1082d3f27b3647c7fef1cfdee77815d77b3967af4fa996efc";
	std::string txidrev = BTCAPI::str_reverse(txid);
	printf("txidrev:\n%s\n", txidrev.c_str());

	std::string str_pubkey_uncompress, str_pubkey_compress;
	str_pubkey_uncompress = "0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf";
	str_pubkey_compress = BTCAPI::compress_pubkey(str_pubkey_uncompress);
	
	str_pubkey_compress = "0387a907e073e338124fb4204cb74932b18489aa425b1e8c3813d2a89bbdfcf2ac";
	str_pubkey_uncompress = BTCAPI::decompress_pubkey(str_pubkey_compress);
	printf("str_pubkey_uncompress:\n%s\n", str_pubkey_uncompress.c_str());
	//printf("str_pubkey_compress:\n%s\n", str_pubkey_compress.c_str());

	std::string str_prikey = "30b430b434ad801cd561fd57c9b083dc3ebe787250e27c367b6599a1a57654f9";
	printf("str_prikey:\n%s\n", str_prikey.c_str());
	str_pubkey_compress = BTCAPI::get_public_key(str_prikey, true);
	printf("str_pubkey_compress:\n%s\n", str_pubkey_compress.c_str());
	str_pubkey_uncompress = BTCAPI::get_public_key(str_prikey, false);
	printf("str_pubkey_uncompress:\n%s\n", str_pubkey_uncompress.c_str());

	std::vector<std::string> vec_pubkeys_compress, vec_pubkeys_uncompress;
	vec_pubkeys_compress.push_back(str_pubkey_compress);
	vec_pubkeys_uncompress.push_back("04" + str_pubkey_uncompress);

	str_prikey = "73cfe03c414a00bcbc502b70c0b1656711fc93e1a44c50fbe0626b79cb66d3ef";
	str_prikey = "2098cee2687f5bd020f358641d4b91e9a1e7e637052795321a40a5032604760a";
	printf("str_prikey:\n%s\n", str_prikey.c_str());
	str_pubkey_compress = BTCAPI::get_public_key(str_prikey, true);
	printf("str_pubkey_compress:\n%s\n", str_pubkey_compress.c_str());
	str_pubkey_uncompress = BTCAPI::get_public_key(str_prikey, false);
	printf("str_pubkey_uncompress:\n%s\n", str_pubkey_uncompress.c_str());

	vec_pubkeys_compress.push_back(str_pubkey_compress);
	vec_pubkeys_uncompress.push_back("04" + str_pubkey_uncompress);

	std::string str_redeem_script = BTCAPI::get_redeem_script(vec_pubkeys_compress, 2, 2);
	printf("str_redeem_script:\n%s\n", str_redeem_script.c_str());	
	std::string str_address = BTCAPI::get_multisign_address(str_redeem_script, false);
	printf("str_address:\n%s\n", str_address.c_str());

	str_redeem_script = BTCAPI::get_redeem_script(vec_pubkeys_uncompress, 2, 2);
	printf("str_redeem_script:\n%s\n", str_redeem_script.c_str());
	str_address = BTCAPI::get_multisign_address(str_redeem_script, false);
	printf("str_address:\n%s\n", str_address.c_str());

	//str_redeem_script = "522102b2920753c34df2992a26c0589acd3718846302b3506dc00ed3a6459df71afb87210291474332c297147d2e7d4e21799b06e0bfffc887813f37a9d90309575849c2262103fc4a74379fe1d253457759dd015cc923929ea4eed7f484bb47ba15da0239896153ae";
	//str_address = BTCAPI::get_multisign_address(str_redeem_script, false);
	//printf("str_address:\n%s\n", str_address.c_str());
}

static void test_segarated_witness_bech32_p2wsh() {
	std::string str_redeem_script = "52210381a90d32c91e44434bd56dd564c4b57c70c64aa42a9eab187bddef570057eed82103ae4bf3955f2ada64671610dc4ef912da53de9af5fbc037d33e92c28a68ca43c22103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae";
	std::string str_addr, str_addr_test;

	//str_addr = "bc1q3tmym7hjvhu888l8ljy37yywx02zl9j3cyw6qaee5cf2cvl30e8sre8n0u";
	//str_addr = "bc1qyy30guv6m5ez7ntj0ayr08u23w3k5s8vg3elmxdzlh8a3xskupyqn2lp5w";
	//str_addr = "bc1qr2495q7w35ejsr4etrycgvxz5cth7dsy5hawxa8fa4wywql32tps8whzel";
	//std::string str_witprog = BTCAPI::bech32_addr_decode(str_addr);
	//printf("witprog:\n%s\n", str_witprog.c_str());

	/*str_redeem_script = "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac";
	str_addr = BTCAPI::get_segwit_address_bech32_p2wsh(false, str_redeem_script);
	printf("Mainnet P2WSH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_segwit_address_bech32_p2wsh(true, str_redeem_script);
	printf("Testnet P2WSH:\n%s\n", str_addr_test.c_str());*/

	//str_redeem_script = "00201aaa5a03ce8d33280eb958c98430c2a6177f3604a5fae374e9ed5c4703f152c3";
	str_addr = BTCAPI::get_segwit_address_bech32_p2wsh_redeem_script(false, str_redeem_script);
	printf("Mainnet P2WSH:\n%s\n", str_addr.c_str());
	str_addr_test = BTCAPI::get_segwit_address_bech32_p2wsh_redeem_script(true, str_redeem_script);
	printf("Testnet P2WSH:\n%s\n", str_addr_test.c_str());
}

static void bech32_p2sh_p2wpkh() {
	std::string str_txid = "e89ac19b0a5b49986a0729c9f9eea2ade00e46d4d60b2e5116a36c7721423f8a";
	std::string str_txid1 = BTCAPI::str_reverse(str_txid);
	printf("txid_rev:\n%s\n", str_txid1.c_str());

	std::string str_redeem_script = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
	//str_redeem_script = "001491b24bf9f5288532960ac687abb035127b1d28a5";
	std::string str_pubkey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	str_pubkey = "02d1dd5a398c11cebca84c91869865813dde916ec3093645b4e2d4f9f5abf6c3d0";
	std::string str_pubunkey = BTCAPI::decompress_pubkey(str_pubkey);

	//std::string str_addr = BTCAPI::get_segwit_address_bech32_p2sh_p2wpkh(false, str_pubkey);
	//printf("str_addr:\n%s\n", str_addr.c_str());
}

void BTCTest()
{
	//test_validate_address();
	//test_get_private_key();
	//test_get_public_key();
	//test_get_address();
	//test_decode_script();
	//test_firmware_sign();
	//test_sign();

	//BTCAPI::dump_tx(false, "0200000005ad65867ffc89aa123f6f949569206e9feaa06f959b39ac28031f636d802a5a0f010000006b483045022100edaf6269014e5ebb048363076b251856bfc320896b389a4fdcfca19969d7b41302207606de5b2da1bbb2969e776483def616ae925e907bcfa1c34ccad81c35dc381e0121034f7d7dbe6383ab7392bd084bc2230a5d71a356d259b63a8211fde7963a6ac54afeffffff86c2bdb1ce6c42b84d161121df052f1fa8879effab70b4e0546b2fdc2894329b9c0000006b483045022100fe1dba1f0cb003d704dd705e0f5fb5d665178bef77083b67abd21feae23642c902205b44a702b67423de6971af3f6e4d9b9856fee67191221439aaf83ac445fbe27e012102250059deda6357b3a6a36e85fdc75b5f8ba626e04c01e54521aa9e8f9f8f67e2feffffff86c2bdb1ce6c42b84d161121df052f1fa8879effab70b4e0546b2fdc2894329bb10000006b483045022100ab4f70ba1ee1ba45337b6d8fe274c75ce58a5d395defd87e7a5ec108f297efcb02204fc3ab48fca57212b442d4a8ee5e45577e5fd7a6d5f82411d009d0db4fba38f2012102e6cd1608a55a5b856a3f5a7009322f2355ceb88c619f59f9792c9843d417efe3feffffff72f7c2a66de0a0e46f848fcbcf81b5be354d1e5f1324ce39bacc20d61e72286e000000006a47304402201e43add83c61ec51b84158628f2f9a2ba9ad143b006bee1285ac7735ed80a5ad0220255b328144c282e83a2c1286ff5f0e08082edc1e33cad6db02b7194f50b2167601210203090a0b9e917ce758bad053aaa0966a6b97fcb7ed02a41b6a40458f9017e648feffffff5bef1f3f09a81ac96bbb1b407ec1d1ca9658025ea99a9e6337ee9ace83fb5830030000006b483045022100cebbfda56777133a51a6152f2a3caba9bdcadbf874ed91810d6fdd927d608eb802201356065851aae6a7aeb51489a4280cd338dfb6dca637f1106b56fece02efd7eb012103b450cd8f896031f75c026772855aeecbc1c3b7d46380046551cbbd9a89a84f39feffffff026ec20c00000000001976a914e1d1d2c42f4b46d85ac3aacf4fda5986fd84b67088ac806532010000000017a914beac82207c8d64e734afeca04ae9977bcfbf5c43877c510800");
	//BTCAPI::dump_tx(false, "010000000132c7dbe543cb6b222a6988ab962064566a27c1077cd281936f7e61373fc5bb5e000000006b48304502210097fc2a813d23bcf56fe2a489d3163b94bfc029edf016856cc72a04208525b46d0220338265898aaaf8e391b3c612885306293aeb2bfe85d82658a34ac47f6bdfc85d012102ae3aabcdefdfd8c990a5d1cad524d0d91257a427eb78112cf7a266484699c30affffffff03409c0000000000001976a91485984864a7e26c3c4a1888373115494a56673b5d88ac0000000000000000166a146f6d6e69000000000000001f000000000098968022020000000000001976a91480d052caee0cbc838f340a5c16c1c708fb0c2ce688ac00000000");
	//BTCAPI::dump_tx(false, "0100000001887e205b6a3d96fa115424bdcc70a739d87078c0212da9ba91440ce9954a0b660000000000ffffffff02c0e1e400000000001976a91478ce9278e94d6de90a22b23fc475883dfbc422d588ac50c30000000000001976a91425322a09dcc10ae461c5ca617818aca8bfc63b3b88ac00000000");

	//BTCAPI::dump_tx(false, "010000000132c7dbe543cb6b222a6988ab962064566a27c1077cd281936f7e61373fc5bb5e000000006b48304502210097fc2a813d23bcf56fe2a489d3163b94bfc029edf016856cc72a04208525b46d0220338265898aaaf8e391b3c612885306293aeb2bfe85d82658a34ac47f6bdfc85d012102ae3aabcdefdfd8c990a5d1cad524d0d91257a427eb78112cf7a266484699c30affffffff03409c0000000000001976a91485984864a7e26c3c4a1888373115494a56673b5d88ac0000000000000000166a146f6d6e69000000000000001f000000000098968022020000000000001976a91480d052caee0cbc838f340a5c16c1c708fb0c2ce688ac00000000");
	//BTCAPI::dump_tx(true, "0100000002f0470a1d58e0e361ac6b73c47a048f81231b4d0d6426152a98814411c3036f54000000006b483045022100da3521feff575301e574fc57f33b089bc4eec838b15cad985b74d6418da8cfc50220408211a0bc4ad2c86fb8dceaba61958eabcc11964272daa46eb23bf72af06731012102d8dce330e3db29d953a579b4bddf0cf76fe264ad7e5a6454fe66fa2a6d31997bffffffffa4a3510644f3b605247c3c23b7ab94068f7db3a70ce9d2a8de8d8837d62da9bd000000006a47304402207480c18626de64a12950a8a818541cf9b39aeded1f99b3329a9f2e7969de7b7302205786c971697d9cf6e165b7d1ab9ea89c57177c9296ae82d98e724c9e941c9fb2012102d8dce330e3db29d953a579b4bddf0cf76fe264ad7e5a6454fe66fa2a6d31997bffffffff02405dc600000000001976a914f711e972a2a9c44e9d03a9c3f650c1ab74fe5ef988ace8c66900000000001976a9148efbde144197c532d5d8bf694375a7b9dcdf704188ac00000000");
	//BTCAPI::dump_tx(true, "0100000001eab24fa00eba0a2a9fd7247485c7880de28b6b59d577b29022af4a011c728f6b010000006a47304402204ae1e0bce8bf142d454ec611f7b1db3d5c18b6ef7ec4886c116b12ef3842349402202d203f5c5b79b86200b639f98a86c55b17c1e1d712bbc59ddf0d8989b30cb68c01210259ac45c55394f2b30daa6db957984f643739a31bf739f736e524cbd35aec4c26ffffffff02002d3101000000001976a9142f57034b6ee54315a481f13e232a1033d42ca7ed88ac00dd8e00000000001976a91406ef16276bdae552ffb5a175a02351e336a1926288ac00000000");

	//GetWalletBalance();
	//test_usdt_sign();

	//sp_test_sign();

	//test_get_multisign_address();
	//test_multisign_tx();
	//test_sign1();

	//test_get_segwit_addr();
	//test_segarated_witness_bech32_p2wpkh_pubkey();
	//test_segwit_address_bech32_p2wsh_pubkey();
	//test_segwit_address_bech32_p2wsh_redeem_script();
	//test_segarated_witness_bip142_p2wpkh();
	//get_segwit_addr();
	//test_segwit_tx();
	compress_convert();

	getchar();
}