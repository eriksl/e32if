#include "packet_header.h"

#include <string>
#include <stdint.h>

class Packet
{
	public:

		Packet() = delete;
		Packet(const Packet &) = delete;

		Packet(bool packetised, bool verbose = false, bool debug = false);

		std::string encapsulate(const std::string &data, const std::string &oob_data) noexcept;
		bool decapsulate(const std::string &packet, std::string &data, std::string &oob_data, bool &raw) noexcept;
		static bool valid(const std::string &packet) noexcept;
		static bool complete(const std::string &packet) noexcept;

	private:

		bool packetised;
		bool verbose;
		bool debug;
};
