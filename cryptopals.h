#ifndef __CRYPTOPALS_H__
#define __CRYPTOPALS_H__

#include <vector>
#include <string>

namespace cryptopals {
	class challenge {
	public:
		virtual void solution(void) = 0;
	};
	static std::byte to_hex(unsigned char c);
	std::vector<std::byte> operator ""_hex(const char* str, std::size_t s);
	std::vector<std::byte> operator ^ (std::vector<std::byte> l, std::vector<std::byte> r);
	std::vector<std::byte> operator ^ (std::vector<std::byte> l, std::byte r);
	std::pair<double, std::byte> most_probable_xor_enc_key(std::vector<std::byte> cbuf);
	std::vector<std::byte> hexstringbytes(std::string s);
	unsigned int hamming_distance(const std::string& s1, const std::string& s2);
	unsigned int hamming_distance(const std::vector<std::byte>& v1, const std::vector<std::byte>& v2);
	std::string readall(std::string filename);
	unsigned int repeated_xor_key_size(const std::vector<std::byte>& v);
	std::vector<std::byte> get_repeated_xor_key(const unsigned int keysize, const std::vector<std::byte>& v);
}

#endif
