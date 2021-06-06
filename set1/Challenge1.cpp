#include <iostream>
#include <vector>
#include <algorithm>
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
}