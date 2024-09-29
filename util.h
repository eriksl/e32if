#pragma once

#include "generic_socket.h"
#include "util.h"
#include "e32_config.h"

#include <string>
#include <vector>

#include <stdint.h>

class Util
{
	public:

		Util() = delete;
		Util(const Util &) = delete;
		Util(GenericSocket *channel, const e32_config &config) noexcept;

		static std::string dumper(const char *id, const std::string text);
		static std::string hash_to_text(unsigned int length, const unsigned char *hash);
		static std::string encrypt_aes_256(std::string input_string);
		static uint32_t crc32cksum_byte(uint32_t crc, void const *mem, size_t len);

		int process(const std::string &data, const std::string &oob_data,
				std::string &reply_data, std::string *reply_oob_data = nullptr,
				const char *match = nullptr, std::vector<std::string> *string_value = nullptr, std::vector<int> *int_value = nullptr, int timeout = -1) const;

	private:

		GenericSocket *channel;
		const e32_config config;
		const static uint32_t crc32_table_byte[];
};
