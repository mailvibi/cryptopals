#include <iostream>
#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <filesystem>
#include <fstream>

#include "common_lib.h"
namespace cryptopals {

	static unsigned char to_hex(unsigned char c)
	{

		if (c > '9')
			c += 9;
		return (c & 0xf);
	}

	std::ostream& operator<<(std::ostream& o, std::vector<unsigned char>& b)
	{
		for (auto i : b)
			o << std::hex << std::setw(2) << std::setfill('0') << int(i) ;
		o << std::endl;
		return o;
	}	
	std::vector<unsigned char> hexstringbytes(std::string s)
	{
		std::size_t i = 0;
		std::vector <unsigned char> r;
		if (s.length() == 0)
			return r;
		if (s.length() & 1) { 
			r.push_back(to_hex(s[0]));
			i = 1;
		}
		while (i < s.length()) {
			r.push_back((to_hex(s[i]) << 4) | to_hex(s[i + 1]));
			i += 2;
		}
		return r;
	}

	std::vector<unsigned char> operator ""_hex(const char* str, std::size_t s)
	{
		std::size_t i = 0;
		std::vector <unsigned char> r;
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

	std::vector<unsigned char> operator ^ (std::vector<unsigned char> l, std::vector<unsigned char> r)
	{
		std::vector<unsigned char> ret{};
		if (l.size() < r.size()) {
			return ret;
		}

		for (auto j = 0, i = 0 ; i < l.size() ; i++, j++) {
			if (j == r.size())
				j = 0;
			ret.push_back(l[i] ^ r[j]);
		}
		return ret;
	}

	std::vector<unsigned char> operator ^ (std::vector<unsigned char> l, unsigned char r)
	{
		std::vector<unsigned char> ret{0};
		if (l.size() == 0) {
			return ret;
		}

		for (auto i : l)
			ret.push_back(i ^ r);
		return ret;
	}

	std::string readall(std::string filename)
	{
		std::ifstream ip;
		ip.open(filename);
		std::string r{};
		if (ip.is_open()) {
			const auto size = std::filesystem::file_size(filename);
			std::string t{std::istreambuf_iterator<char>(ip), std::istreambuf_iterator<char>()};
			r.reserve(size);
			auto it = std::copy_if(std::begin(t), std::end(t), std::back_inserter(r),[](char i) { return (i != '\n' && i != '\r'); });
			r.shrink_to_fit();
		}
		return r;
	}


}