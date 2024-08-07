#pragma once

#include "generic_socket.h"
#include "util.h"
#include "e32_config.h"

#include <string>
#include <vector>

class Util
{
	public:

		Util() = delete;
		Util(const Util &) = delete;
		Util(GenericSocket *channel, const e32_config &config) noexcept;

		static std::string dumper(const char *id, const std::string text);
		static std::string hash_to_text(unsigned int length, const unsigned char *hash);
		static std::string encrypt_aes_256(std::string input_string);

		int process(const std::string &data, const std::string &oob_data,
				std::string &reply_data, std::string *reply_oob_data = nullptr,
				const char *match = nullptr, std::vector<std::string> *string_value = nullptr, std::vector<int> *int_value = nullptr, int timeout = -1) const;
		int read_sector(unsigned int sector_size, unsigned int sector, std::string &data, int timeout = -1) const;
		int write_sector(unsigned int sector, const std::string &data,
				unsigned int &written, unsigned int &erased, unsigned int &skipped, bool simulate) const;
		void get_checksum(unsigned int sector, unsigned int sectors,
				std::string &checksum, int timeout = -1) const;

	private:

		GenericSocket *channel;
		const e32_config config;
};
