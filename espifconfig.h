#ifndef _espifconfig_h_
#define _espifconfig_h_

#include <string>

typedef enum
{
	transport_none,
	transport_tcp_ip,
	transport_udp_ip,
	transport_bluetooth,
} config_transport_t;

class EspifConfig
{
	public:

		std::string host;
		std::string command_port = "24";
		config_transport_t transport = transport_none;
		bool broadcast = false;
		bool multicast = false;
		bool debug = false;
		bool verbose = false;
		bool dontwait = false;
		unsigned int broadcast_group_mask = 0;
		unsigned int multicast_burst = 3;
		bool raw = false;
		bool provide_checksum = true;
		bool request_checksum = true;
		unsigned int sector_size = 4096;
};

#endif
