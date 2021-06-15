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
	static const double max_eng_lang_score = .80;

	static std::byte to_hex(unsigned char c)
	{

		if (c > '9')
			c += 9;
		return std::byte(c & 0xf);
	}

	std::vector<std::byte> hexstringbytes(std::string s)
	{
		std::size_t i = 0;
		std::vector <std::byte> r;
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
		std::vector<std::byte> ret{};
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

	std::byte most_frequent_byte(std::vector<std::byte> buf)
	{
		std::array<unsigned int, 256> freq_map{0};
		std::pair<std::byte, unsigned int> most_freq {std::byte{0},0};

		for (auto i : buf) {
			++freq_map[std::to_integer<int>(i)];
			if (freq_map[std::to_integer<int>(i)] > most_freq.second) {
				most_freq.first = i;
				most_freq.second = freq_map[std::to_integer<int>(i)];
			}
		}
		return most_freq.first;
	}

	double english_language_score(std::vector<std::byte> buf)
	{
		double score = 0.0;
		unsigned int alphachars = 0;
		for (auto i : buf) {
			if (auto v = std::to_integer<int>(i) ; std::isalpha(v) || std::isspace(v))
				alphachars++;
		}
		score = (double)alphachars/buf.size();
		return score;
	}

	std::pair<double, std::byte> most_probable_xor_enc_key(std::vector<std::byte> cbuf)
	{
		std::pair<double, std::byte> max_score_key{0,std::byte(0)};
		const std::array<char, 26> eng_char_freq_map = {"ETAOIN SHRDLUetaoinshrdlu"};
		auto freq_byte = most_frequent_byte(cbuf);
		for (auto i : eng_char_freq_map) {
			std::byte tmpkey = std::byte(i) ^ freq_byte;
			auto pbuf = cbuf ^ tmpkey;
			auto eng_prob_score = english_language_score(pbuf);
			if (eng_prob_score > max_score_key.first) {
				max_score_key.first = eng_prob_score;
				max_score_key.second = tmpkey;
			}
		}
		if (max_score_key.first > max_eng_lang_score) {
/* 			std::string s;
			auto pbuf = cbuf ^ max_score_key.second;
			for (auto k : pbuf)
				s.push_back(std::to_integer<char>(k));
			std::cout << "Probable plain text : " << s << std::endl ; */
		}
		return max_score_key;
	}
}

