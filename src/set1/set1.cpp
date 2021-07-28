#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <unordered_set>
#include "common_lib.h"
#include "wcrypto.h"
#include "xor_enc.h"
#include "base64.h"
#include "set1.h"

namespace cryptopals::set1 {
	void challenge1(void)
	{
		auto a = "9276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"_hex;
		auto str = b64::encode(a);
		std::cout << "Challenge 1 : " << str << std::endl;
	}
	void challenge2(void) 
	{
		auto h1 = "1c0111001f010100061a024b53535009181c"_hex;
		auto h2 = "686974207468652062756c6c277320657965"_hex;
		auto o = h1 ^ h2;
		std::cout << "Challenge 2 : "; 
		//std::for_each(o.begin(), o.end(), [](unsigned char i) {std::cout << std::hex << i << ",";});
		std::cout << o;//std::endl;
	}
	void challenge3(void)
	{
		auto c = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"_hex;
	  	auto key = most_probable_xor_enc_key(c);
		std::string s;
		auto pbuf = c ^ key.second;
		for (auto k : pbuf)
			s.push_back(k);
		std::cout << "Challenge 3 : Key => " << std::hex << int(key.second) << std::endl;
		std::cout << "\tDecrypted plain text : " << s << std::endl ;
	}
	void challenge4(void)
	{
		std::string filename{"./set1/4.txt"}, line;
		std::ifstream ipfile(filename);
		int linenum = 0;
		std::pair<std::pair<double, unsigned char>, std::vector<unsigned char>> probable_key_info_n_line {};
		if (!ipfile.is_open()) {
			std::cout << "error in opening file :" << filename << std::endl;
			return ;
		}
		while (std::getline(ipfile, line)) {
			++linenum;
			auto b = hexstringbytes(line);
			auto key = most_probable_xor_enc_key(b);
			if (key.first > probable_key_info_n_line.first.first) {
				probable_key_info_n_line.first = key;
				probable_key_info_n_line.second = b;
			}
		}
		auto p = probable_key_info_n_line.second ^ probable_key_info_n_line.first.second;
		line.clear();
		for (auto k : p)
			line.push_back(k);
		std::cout << "Challenge 4 : Key => " << std::hex << int(probable_key_info_n_line.first.second) << std::endl;
		std::cout << "\tDecrypted plain text : " << line << std::endl ;
	}
	void challenge5(void)
	{
		std::string pstr{"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"};
		std::string keystr{"ICE"};
		auto strtob = [](std::string s) -> std::vector<unsigned char> { std::vector<unsigned char> r; for (auto i : s) r.push_back(i); return r;};
		auto p = strtob(pstr);
		auto k = strtob(keystr);
		auto c = p ^ k;
		std::cout << p;
		std::cout << k;
		std::cout << "Challenge 5 : " ;
		std::cout << c;
	}
	void challenge6(void)
	{
		std::string s1{"this is a test"}, s2{"wokka wokka!!!"};
		auto hd_s = hamming_distance(s1, s2);
		std::cout << "Challenge 6 : " << std::endl;
		std::cout << "Hamming distance between \" " << s1 << "\" & \"" << s2 << "\" = " << std::dec << hd_s << std::endl;
		auto prntByteVector = [](std::vector<unsigned char>& v) {std::for_each(v.begin(), v.end(), [](unsigned char i) {std::cout << std::hex << i;}); std::cout << std::endl;};
		std::string ipdata = readall("./set1/6.txt");
		const auto data = b64::decode(ipdata);		
		auto keysz = repeated_xor_key_size(data);
		auto key = get_repeated_xor_key(keysz, data);
		//prntByteVector(key);
		auto c = data ^ key;
		std::for_each(c.begin(), c.end(), [](unsigned char i) {std::cout << char(i);});
	}

	void challenge7(void)
	{
		std::string ipdata = readall("./set1/7.txt");
		const std::string skey{"YELLOW SUBMARINE"};
		aes128Key key;
		skey.copy(reinterpret_cast<char*>(key.data()),skey.length()); 
	
		std::cout << "Challenge 7 : " << std::endl;
	
		const auto data = b64::decode(ipdata);
		//auto btochr = [](const byteVector &v) -> std::vector<unsigned char>{std::vector<unsigned char> r; for(auto i : v) r.push_back(std::to_integer<unsigned char>(i)); return r;};
		//auto cb = btochr(data);
		auto pv = aes128_ecb_decrypt(data, key);
		if (pv.size())
			std::for_each(pv.begin(), pv.end(), [](auto i) {std::cout << i ;});
		else
			std::cout << "error in decrypting" << std::endl;
	}

	struct ByteVectorHash {
		size_t operator()(const std::vector<unsigned char>& v) const {
			std::hash<unsigned char> hasher;
			size_t seed = 0;
			for (auto i : v) {
				seed ^= hasher(i) << 1;
			}
			return seed;
		}
	};

	void challenge8(void)
	{
		std::string filename{"./set1/8.txt"}, line;
		std::ifstream ipfile(filename);
		int linenum = 0;
		auto prntByteVector = [](std::vector<unsigned char>& v) {std::for_each(v.begin(), v.end(), [](unsigned char i) {std::cout << std::hex << std::setfill('0') << std::setw(2)<< i;}); std::cout << std::endl;};
		std::cout << "Challenge 8 : " << std::endl;

		while (std::getline(ipfile, line)) {
			++linenum;
			auto b = hexstringbytes(line);	
			std::unordered_multiset<std::vector<unsigned char>, ByteVectorHash> s;
			for (auto i = 0 ; i < b.size() - 15 ; i += 16) {
				std::vector<unsigned char> v{b.begin() + i, b.begin() + i + 16};
				s.insert(v);
			}
			for (auto i : s)
				if (auto j = s.count(i) ; j > 1) {
					std::cout << "probable ECB @ line = " << linenum << " pattern count repeated = " << j << std::endl;
					break;
				}

		}
	}
	void solution(void)
	{
		challenge1();
		challenge2();
		challenge3();
		challenge4();
		challenge5();
		challenge6();
		challenge7();
		challenge8();
	}
}

int main()
{
	cryptopals::set1::solution();
}