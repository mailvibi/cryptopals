#ifndef __COMMON_LIB_H__
#define __COMMON_LIB_H__

#include <vector>
#include <string>

namespace cryptopals {
	std::string readall(std::string filename);
	static unsigned char to_hex(unsigned char c);
	std::ostream& operator<<(std::ostream& o, std::vector<unsigned char>& b);
	std::vector<unsigned char> operator ""_hex(const char* str, std::size_t s);
	std::vector<unsigned char> operator ^ (std::vector<unsigned char> l, std::vector<unsigned char> r);
	std::vector<unsigned char> operator ^ (std::vector<unsigned char> l, unsigned char r);
	std::vector<unsigned char> hexstringbytes(std::string s);
}
#endif /*__COMMON_LIB_H__ */


