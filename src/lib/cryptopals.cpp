// cryptopals.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <filesystem>
#include <fstream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "common_lib.h"
#include "wcrypto.h"
#include "xor_enc.h"

namespace cryptopals {

	static const double max_eng_lang_score = .80;

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

	unsigned char most_frequent_byte(std::vector<unsigned char> buf)
	{
		std::array<unsigned int, 256> freq_map{0};
		std::pair<unsigned char, unsigned int> most_freq {0,0};

		for (auto i : buf) {
			++freq_map[i];
			if (freq_map[i] > most_freq.second) {
				most_freq.first = i;
				most_freq.second = freq_map[i];
			}
		}
		return most_freq.first;
	}

	double english_language_score(std::vector<unsigned char> buf)
	{
		double score = 0.0;
		unsigned int alphachars = 0;
		for (auto i : buf) {
			if (std::isalpha(i) || std::isspace(i))
				alphachars++;
		}
		score = (double)alphachars/buf.size();
		return score;
	}

	std::pair<double, unsigned char> most_probable_xor_enc_key(std::vector<unsigned char> cbuf)
	{
		std::pair<double, unsigned char> max_score_key{0,0};
		const std::array<char, 26> eng_char_freq_map = {"ETAOIN SHRDLUetaoinshrdlu"};
		auto freq_byte = most_frequent_byte(cbuf);
		for (auto i : eng_char_freq_map) {
			unsigned char tmpkey = i ^ freq_byte;
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

	unsigned int hamming_distance(const std::vector<unsigned char>& v1, const std::vector<unsigned char>& v2)
	{
		unsigned int hd = 0;
		if ((v1.size() == 0) || (v1.size() != v2.size())) {
			return hd;
		}
		for (int i = 0 ; i < v1.size() ; i++) {
			for (unsigned char t = v1[i] ^ v2[i] ; t != static_cast<unsigned char>(0) ; t >>= 1)
				if ((t & static_cast<unsigned char>(1)) == static_cast<unsigned char>(1))
					hd++;
		}
		return hd;
 
	}
	
	unsigned int repeated_xor_key_size(const std::vector<unsigned char>& v)
	{
		std::pair<unsigned int, unsigned int> lowestHdKey{0, 0xFFFFFFFF};
		const auto max_samples = 10;
		const auto max_keysz = 40;
		for (unsigned int ks = 2 ; ks < max_keysz ; ks++) {
			unsigned int tmp_hd = 0;
			for (int offset = 0, sample_nums = 0  ; (sample_nums < max_samples) && (((max_samples + 1) * ks) <= v.size()) ; sample_nums++, offset += ks) {
				std::vector<unsigned char> v1{v.begin() + offset, v.begin() + offset + ks};
				std::vector<unsigned char> v2{v.begin() + offset + ks, v.begin() + offset + ks + ks};
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
	
	std::vector<unsigned char> get_repeated_xor_key(const unsigned int keysize, const std::vector<unsigned char>& v)
	{
		std::vector<unsigned char>tmp {/*v.size()/keysize*/};
		std::vector<unsigned char>key{};
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
	std::vector<unsigned char> aes128_ecb_decrypt(const std::vector<unsigned char>& c, const aes128Key& key)
	{
		int ret = 0, len = 0, l = 0;
		std::vector<unsigned char> p;
		p.resize(c.size() + 256);
		EVP_add_cipher(EVP_aes_128_ecb());
		auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

		ret = EVP_DecryptInit(ctx.get(), EVP_aes_128_ecb(), key.data(), NULL);
		if (ret != 1) {
			std::cout << "error dec init" << std::endl;
			return p;
		}
		EVP_CIPHER_CTX_set_key_length(ctx.get(), 16);
		EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
		ret = EVP_DecryptUpdate(ctx.get(), p.data(), &len, c.data(), c.size());
		if (ret != 1) {
			std::cout << "error dec update" << std::endl;
			return p;
		}
		l = len;		
		ret = EVP_DecryptFinal(ctx.get(), p.data() + len, &len);
		if (ret != 1)  {
			std::cout << "error dec final (len = " << len <<" - " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			return p;
		}
		l += len;
		p.resize(l);
		return p;
	}
}