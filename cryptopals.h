#ifndef __CRYPTOPALS_H__
#define __CRYPTOPALS_H__

#include <vector>
#include <string>
#include <array>

namespace cryptopals {
	class challenge {
	public:
		virtual void solution(void) = 0;
	};
	using byteVector = std::vector<unsigned char>;
	using aesKey = std::array<unsigned char, 16>;

	static unsigned char to_hex(unsigned char c);
	std::ostream& operator<<(std::ostream& o, std::vector<unsigned char>& b);
	std::vector<unsigned char> operator ""_hex(const char* str, std::size_t s);
	std::vector<unsigned char> operator ^ (std::vector<unsigned char> l, std::vector<unsigned char> r);
	std::vector<unsigned char> operator ^ (std::vector<unsigned char> l, unsigned char r);
	std::pair<double, unsigned char> most_probable_xor_enc_key(std::vector<unsigned char> cbuf);
	std::vector<unsigned char> hexstringbytes(std::string s);
	unsigned int hamming_distance(const std::string& s1, const std::string& s2);
	unsigned int hamming_distance(const std::vector<unsigned char>& v1, const std::vector<unsigned char>& v2);
	std::string readall(std::string filename);
	unsigned int repeated_xor_key_size(const std::vector<unsigned char>& v);
	std::vector<unsigned char> get_repeated_xor_key(const unsigned int keysize, const std::vector<unsigned char>& v);
	
	std::vector<unsigned char> aes128_ecb_decrypt(const std::vector<unsigned char>& c, const aesKey& key);
	
}

#endif
