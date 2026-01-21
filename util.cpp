#include "util.h"
#include "exception.h"

#include <string>
#include <iostream>
#include <typeinfo>
#include <boost/format.hpp>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

void Util::time_to_string(std::string &dst, const time_t &ticks)
{
    struct tm tm;
    char timestring[64];

    localtime_r(&ticks, &tm);
    strftime(timestring, sizeof(timestring), "%Y/%m/%d %H:%M:%S", &tm);

	dst = timestring;
}

std::string Util::dumper(const char *id, const std::string text)
{
	int ix;
	char current;
	std::string out;

	out = (boost::format("%s[%d]: \"") % id % text.length()).str();

	for(ix = 0; (ix < (int)text.length()) && (ix < 512); ix++)
	{
		current = text.at(ix);

		if((current >= ' ') && (current <= '~'))
			out.append(1, current);
		else
			out.append((boost::format("[%02x]") % ((unsigned int)current & 0xff)).str());
	}

	out.append("\"");

	return(out);
}
