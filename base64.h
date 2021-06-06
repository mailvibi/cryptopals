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
			static std::string encode(std::vector<std::byte>& bytes)
			{
				const std::string& b64encode_map = get_encodeMap();
				if (bytes.size() == 0) {
					return std::string{};
				}
				auto s = (bytes.size() + 2) / 3 * 4;
				std::string ret;
				unsigned int i = 0;
				for (; i < bytes.size() - 2; i += 3) {
					ret.push_back(b64encode_map[std::to_integer<int>(bytes[i]) >> 2]);
					ret.push_back(b64encode_map[((std::to_integer<int>(bytes[i]) & 0x3) << 4) | ((std::to_integer<int>(bytes[i + 1]) >> 4) & 0xf)]);
					ret.push_back(b64encode_map[((std::to_integer<int>(bytes[i + 1]) & 0xf) << 2) | ((std::to_integer<int>(bytes[i + 2]) >> 6) & 0x3)]);
					ret.push_back(b64encode_map[std::to_integer<int>(bytes[i + 2]) & 0x3f]);
				}
				if (i < bytes.size()) {
					ret.push_back(b64encode_map[std::to_integer<int>(bytes[i]) >> 2]);
					ret.push_back(b64encode_map[(std::to_integer<int>(bytes[i]) & 0x3) << 4]);
					if ((i + 1) < bytes.size()) {
						ret.push_back(b64encode_map[((std::to_integer<int>(bytes[i]) & 0x3) << 4) | ((std::to_integer<int>(bytes[i + 1]) >> 4) & 0xf)]);
						ret.push_back(b64encode_map[(std::to_integer<int>(bytes[i + 1]) & 0xf) << 2]);
					}
					else {
						ret.push_back('=');
					}
					ret.push_back('=');
				}
				return ret;
			}
		private :
			static const std::string& get_encodeMap(void) {
				static const std::string encode_map = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
				return encode_map;
			}
	};
}