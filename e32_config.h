#pragma once

#include <string>

typedef enum
{
	transport_none = 0,
	transport_tcp_ip = 1,
	transport_udp_ip = 2,
	transport_bluetooth = 3,
} config_transport_t;

struct e32_config
{
	std::string host;
	std::string command_port = "24";
	config_transport_t transport = transport_none;
	bool debug = false;
	bool verbose = false;
	bool raw = false;
	unsigned int sector_size = 4096;
};
