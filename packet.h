#include "packet_header.h"

#include <string>
#include <stdint.h>

class Packet
{
	public:

		Packet() = delete;
		Packet(const Packet &) = delete;

		static bool valid(const std::string &packet);
		static bool complete(const std::string &packet);
		static std::string encapsulate(const std::string &data, const std::string &oob_data, bool packetised = true, bool verbose = false, bool debug = false);
		static bool decapsulate(const std::string &packet, std::string &data, std::string &oob_data, bool packetised = true, bool verbose = false, bool debug = false);
};
