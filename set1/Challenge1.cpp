#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include "cryptopals.h"
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
		std::for_each(o.begin(), o.end(), [](std::byte i) {std::cout << std::hex << std::to_integer<int>(i) << ",";});
		std::cout << std::endl;
	}
	void challenge3(void)
	{
		auto c = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"_hex;
	  	auto key = most_probable_xor_enc_key(c);
		std::string s;
		auto pbuf = c ^ key.second;
		for (auto k : pbuf)
			s.push_back(std::to_integer<char>(k));
		std::cout << "Challenge 3 : Key => " << std::to_integer<int>(key.second) << std::endl;
		std::cout << "\tDecrypted plain text : " << s << std::endl ;
	}
	void challenge4(void)
	{
		std::string filename{"set1/4.txt"}, line;
		std::ifstream ipfile(filename);
		int linenum = 0;
		std::pair<std::pair<double, std::byte>, std::vector<std::byte>> probable_key_info_n_line {};
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
			line.push_back(std::to_integer<char>(k));
		std::cout << "Challenge 4 : Key => " << std::to_integer<int>(probable_key_info_n_line.first.second) << std::endl;
		std::cout << "\tDecrypted plain text : " << line << std::endl ;
	}
	void challenge5(void)
	{
		std::string pstr{"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"};
		std::string keystr{"ICE"};
		auto strtob = [](std::string s) -> std::vector<std::byte> { std::vector<std::byte> r; for (auto i : s) r.push_back(std::byte(i)); return r;};
		auto prntByteVector = [](std::vector<std::byte>& v) {std::for_each(v.begin(), v.end(), [](std::byte i) {std::cout << std::hex << std::to_integer<int>(i);}); std::cout << std::endl;};
		auto p = strtob(pstr);
		auto k = strtob(keystr);
		auto c = p ^ k;
		prntByteVector(p);
		prntByteVector(k);
		std::cout << "Challenge 5 : " ;
		prntByteVector(c);
	}
	void challenge6(void)
	{
		std::string s1{"this is a test"}, s2{"wokka wokka!!!"};
		auto hd_s = hamming_distance(s1, s2);
		std::cout << "Challenge 6 : " << std::endl;
		std::cout << "Hamming distance between \" " << s1 << "\" & \"" << s2 << "\" = " << std::dec << hd_s << std::endl;
		auto prntByteVector = [](std::vector<std::byte>& v) {std::for_each(v.begin(), v.end(), [](std::byte i) {std::cout << std::hex << std::to_integer<int>(i);}); std::cout << std::endl;};
		std::string ipdata = readall("./set1/6.txt");
		const auto data = b64::decode(ipdata);		
		auto keysz = repeated_xor_key_size(data);
		auto key = get_repeated_xor_key(keysz, data);
		//prntByteVector(key);
		auto c = data ^ key;
		std::for_each(c.begin(), c.end(), [](std::byte i) {std::cout << char(std::to_integer<int>(i));});
		
	}
}
