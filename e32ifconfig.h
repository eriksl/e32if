#ifndef _e32ifconfig_h_
#define _e32ifconfig_h_

#include <string>

typedef enum
{
	transport_none = 0,
	transport_tcp_ip = 1,
	transport_udp_ip = 2,
	transport_bluetooth = 3,
} config_transport_t;

class E32IfConfig
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
