// cryptopals.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <filesystem>
#include <fstream>
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
		return max_score_key;
	}
	
	unsigned int hamming_distance(const std::string& s1, const std::string& s2)
	{
		unsigned int hd = 0;
		if ((s1.length() == 0) || (s1.length() != s2.length())) {
			return hd;
		}
//		std::cout << "length = "<< s1.length() << " args = " << s1 << " & " << s2 << std::endl; 
		for (int i = 0 ; i < s1.length() ; i++) {
//			std::cout << " i = " << s1[i] << "|" << s2[i] << " " << (s1[i] ^ s2[i]) << " hd = " << hd << std::endl;
			for (unsigned char t = s1[i] ^ s2[i] ; t ; t >>= 1)
				if (t & 1)
					hd++;
		}
		return hd;	
	}

	std::string readall(std::string filename)
	{
		std::ifstream ip{filename};
		const auto size = std::filesystem::file_size(filename);
		std::string t{std::istreambuf_iterator<char>(ip), std::istreambuf_iterator<char>()};
		std::string r{};
		r.reserve(size);
		auto it = std::copy_if(std::begin(t), std::end(t), std::back_inserter(r),[](char i) { return !(i == '\n' || i == '\r'); });
		r.shrink_to_fit();	
		return r;
	}

	unsigned int hamming_distance(const std::vector<std::byte>& v1, const std::vector<std::byte>& v2)
	{
		unsigned int hd = 0;
		if ((v1.size() == 0) || (v1.size() != v2.size())) {
			return hd;
		}
		for (int i = 0 ; i < v1.size() ; i++) {
			for (std::byte t = v1[i] ^ v2[i] ; t != static_cast<std::byte>(0) ; t >>= 1)
				if ((t & static_cast<std::byte>(1)) == static_cast<std::byte>(1))
					hd++;
		}
		return hd;
 
	}
	
	unsigned int repeated_xor_key_size(const std::vector<std::byte>& v)
	{
		std::pair<unsigned int, unsigned int> lowestHdKey{0, 0xFFFFFFFF};
		const auto max_samples = 10;
		const auto max_keysz = 40;
		for (unsigned int ks = 2 ; ks < max_keysz ; ks++) {
			unsigned int tmp_hd = 0;
			for (int offset = 0, sample_nums = 0  ; (sample_nums < max_samples) && (((max_samples + 1) * ks) <= v.size()) ; sample_nums++, offset += ks) {
				std::vector<std::byte> v1{v.begin() + offset, v.begin() + offset + ks};
				std::vector<std::byte> v2{v.begin() + offset + ks, v.begin() + offset + ks + ks};
				auto t = hamming_distance(v1, v2);
				//std::cout << "key size = " << ks << " hamming_distance = " << t << std::endl;
				tmp_hd += t;
			}
			//std::cout << "key size = " << ks << " hamming_distance = " << tmp_hd << " final hamming_distance = " << tmp_hd / ks << std::endl;
			tmp_hd /= ks;
			if (lowestHdKey.second > tmp_hd) {
				lowestHdKey.second = tmp_hd;
				lowestHdKey.first = ks;
			}
		}
		return lowestHdKey.first;
	}
	
	std::vector<std::byte> get_repeated_xor_key(const unsigned int keysize, const std::vector<std::byte>& v)
	{
		std::vector<std::byte>tmp {v.size()/keysize};
		std::vector<std::byte>key{};
		for (unsigned int i = 0, blks = v.size()/keysize ; i < keysize ; i++) {
			tmp.clear();
			for (unsigned int j = 0; j < blks ; j++) {
				tmp.push_back(v.at((j * keysize) + i));
			}
			auto k = most_probable_xor_enc_key(tmp);
			key.push_back(k.second);
//			std::cout << "key[" << i << "] = " << std::to_integer<int>(k.second) << std::endl; 
		}
		return key;
	}
}