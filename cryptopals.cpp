// cryptopals.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <array>
#include "cryptopals.h"
#include "base64.h"

namespace cryptopals {

	template<typename ...Args>
	inline void log(Args && ...args)
	{
		std::cerr << __LINE__ << " " << __FILE__;
		(std::cout << ... << args);
	}

	static std::byte to_hex(unsigned char c)
	{

		if (c > '9')
			c += 9;
		return std::byte(c & 0xf);
	}

	std::vector<std::byte> operator ""_hex(const char* str, std::size_t s)
	{
		std::size_t i = 0;
		std::vector <std::byte> r;
		if (s == 0)
			return r;
		if (s & 1) {
			r.push_back(to_hex(str[0]));
			i = 1;
		}
		while (i < s) {
			r.push_back((to_hex(str[i]) << 4) | to_hex(str[i + 1]));
			i += 2;
		}
		return r;
	}
	std::vector<std::byte> operator ^ (std::vector<std::byte> l, std::vector<std::byte> r)
	{
		std::vector<std::byte> ret{std::byte{0}};
		if (l.size() != r.size()) {
			return ret;
		}
		
		for (auto i = 0 ; i < l.size() ; i++)
			ret.push_back(l[i] ^ r[i]);
		return ret;
	}

	std::vector<std::byte> operator ^ (std::vector<std::byte> l, std::byte r)
	{
		std::vector<std::byte> ret{std::byte{0}};
		if (l.size() == 0) {
			return ret;
		}

		for (auto i : l)
			ret.push_back(i ^ r);
		return ret;
	}
	
	double english_language_score(std::vector<std::byte> text)
	{
		double score = 0.0;
		return score;
	}

	std::byte most_probable_xor_enc_key(std::string ctext)
	{
		std::byte ret;
		const std::array<char, 26> freq = {"ETAOIN SHRDLUetaoinshrdlu"};
		
		return ret;
	}
}
