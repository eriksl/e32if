#pragma once

#include "util.h"

#include <stdint.h>
#include <string>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

class Util
{
	public:

		Util(const Util &) = delete;

		static void time_to_string(std::string &dst, const time_t &ticks);
		static std::string dumper(const char *id, const std::string text);

	private:
};
