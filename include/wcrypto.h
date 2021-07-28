#ifndef __WCRYPTO_H__
#define __WCRYPTO_H__

#include <vector>
#include <array>

namespace cryptopals {
	using aes128Key = std::array<unsigned char, 16>;

	std::vector<unsigned char> get_repeated_xor_key(const unsigned int keysize, const std::vector<unsigned char>& v);
	std::vector<unsigned char> aes128_ecb_decrypt(const std::vector<unsigned char>& c, const aes128Key& key);
}
#endif /* __WCRYPTO_H__ */