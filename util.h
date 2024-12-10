#pragma once

#include "util.h"

#include <stdint.h>
#include <string>

class Util
{
	public:

		Util(const Util &) = delete;

		static std::string dumper(const char *id, const std::string text);
		static std::string hash_to_text(unsigned int length, const unsigned char *hash);
		static std::string encrypt_aes_256(std::string input_string);
		static uint32_t crc32cksum_byte(uint32_t crc, void const *mem, size_t len);

	private:

		const static uint32_t crc32_table_byte[];
};
