#include "packet_header.h"

#include <string>
#include <stdint.h>

class Packet
{
	public:

		Packet(const Packet &) = delete;
		static std::string encapsulate(const std::string &data, const std::string &oob_data, bool raw) noexcept;
		static bool decapsulate(const std::string &packet, std::string &data, std::string &oob_data, bool &raw, bool verbose) noexcept;
		static bool valid(const std::string &packet) noexcept;
		static bool complete(const std::string &packet) noexcept;
};
