#ifndef __CRYPTOPALS_H__
#define __CRYPTOPALS_H__

#include <vector>
#include <string>
#include <array>

namespace cryptopals {
	using byteVector = std::vector<unsigned char>;

	std::pair<double, unsigned char> most_probable_xor_enc_key(std::vector<unsigned char> cbuf);
	unsigned int hamming_distance(const std::string& s1, const std::string& s2);
	unsigned int hamming_distance(const std::vector<unsigned char>& v1, const std::vector<unsigned char>& v2);
	unsigned int repeated_xor_key_size(const std::vector<unsigned char>& v);
}

#endif
