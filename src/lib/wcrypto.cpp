#include <iostream>
#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <filesystem>
#include <fstream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "wcrypto.h"
namespace cryptopals {
	std::vector<unsigned char> aes128_ecb_decrypt(const std::vector<unsigned char>& c, const aes128Key& key)
	{
		int ret = 0, len = 0, l = 0;
		std::vector<unsigned char> p;
		p.resize(c.size() + 256);
		EVP_add_cipher(EVP_aes_128_ecb());
		auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

		ret = EVP_DecryptInit(ctx.get(), EVP_aes_128_ecb(), key.data(), NULL);
		if (ret != 1) {
			std::cout << "error dec init" << std::endl;
			return p;
		}
		EVP_CIPHER_CTX_set_key_length(ctx.get(), 16);
		EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
		ret = EVP_DecryptUpdate(ctx.get(), p.data(), &len, c.data(), c.size());
		if (ret != 1) {
			std::cout << "error dec update" << std::endl;
			return p;
		}
		l = len;		
		ret = EVP_DecryptFinal(ctx.get(), p.data() + len, &len);
		if (ret != 1)  {
			std::cout << "error dec final (len = " << len <<" - " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			return p;
		}
		l += len;
		p.resize(l);
		return p;
	}
}