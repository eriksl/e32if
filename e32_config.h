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
