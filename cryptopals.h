#ifndef __CRYPTOPALS_H__
#define __CRYPTOPALS_H__

#include <vector>

namespace cryptopals {
	class challenge {
	public:
		virtual void solution(void) = 0;
	};
	static std::byte to_hex(unsigned char c);
	std::vector<std::byte> operator ""_hex(const char* str, std::size_t s);
	std::vector<std::byte> operator ^ (std::vector<std::byte> l, std::vector<std::byte> r);
	std::vector<std::byte> operator ^ (std::vector<std::byte> l, std::byte r);

}

#endif
