#pragma once
#include <iostream>
#include <vector>
#include <cstddef>


#if 0
#define _prn(_x_, ...) do { fprintf(stderr, "["_x_"][%s@%d] : ", __FUNCTION__, __LINE__); \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
  } while (0)

#define err(...) _prn("ERR", __VA_ARGS__)
#define info(...) _prn("INFO", __VA_ARGS__)
#define dbg(...) do { if (__debug__) _prn("DBG", __VA_ARGS__); } while (0)

#endif 

namespace cryptopals {
	class b64 {
		public:
			static std::string encode(std::vector<unsigned char>& bytes)
			{
				const std::string& b64encode_map = get_encodeMap();
				if (bytes.size() == 0) {
					return std::string{};
				}
				auto s = (bytes.size() + 2) / 3 * 4;
				std::string ret;
				unsigned int i = 0;
				for (; i < bytes.size() - 2; i += 3) {
					ret.push_back(b64encode_map[bytes[i] >> 2]);
					ret.push_back(b64encode_map[((bytes[i] & 0x3) << 4) | ((bytes[i + 1] >> 4) & 0xf)]);
					ret.push_back(b64encode_map[((bytes[i + 1] & 0xf) << 2) | ((bytes[i + 2] >> 6) & 0x3)]);
					ret.push_back(b64encode_map[bytes[i + 2] & 0x3f]);
				}
				if (i < bytes.size()) {
					ret.push_back(b64encode_map[bytes[i] >> 2]);
					ret.push_back(b64encode_map[(bytes[i] & 0x3) << 4]);
					if ((i + 1) < bytes.size()) {
						ret.push_back(b64encode_map[((bytes[i] & 0x3) << 4) | ((bytes[i + 1] >> 4) & 0xf)]);
						ret.push_back(b64encode_map[(bytes[i + 1] & 0xf) << 2]);
					}
					else {
						ret.push_back('=');
					}
					ret.push_back('=');
				}
				return ret;
			}
			static std::vector<unsigned char> decode(const std::string& s)
			{
				std::vector<unsigned char> ret;
				auto decode_map = get_decodeMap();
				if(s.length() % 4) {
					std::cout << "input string not multiple of 4 " << std::endl;
					return ret;
				}
				auto p = s.c_str();
				for (int i = 0; i < s.length() ; i += 4) {
					unsigned char b;
					b = decode_map[p[i]] << 2; 
					b |= (decode_map[p[i + 1]] >> 4) & 3;
					ret.push_back(b);
					
					b = decode_map[static_cast<unsigned int>(p[i + 1])] << 4; 
					b |= decode_map[static_cast<unsigned int>(p[i + 2])] >> 2;
					ret.push_back(b);

					b = (decode_map[p[i + 2]] & 3) << 6; 
					b |= decode_map[p[i + 3]];
					ret.push_back(b);
				}
				return ret;
			}
		private :
			static const std::string& get_encodeMap(void) {
				static const std::string encode_map = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
				return encode_map;
			}
			static std::array<unsigned char, 256>& get_decodeMap(void) {
				static std::array<unsigned char, 256>decode_map{};
				auto s = get_encodeMap();
				unsigned int i = 0;
				for (auto& c : s) {
					decode_map[c] = i;
					++i;
				}
				return decode_map;
			}
	};
}