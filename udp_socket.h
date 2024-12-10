#pragma once

#include "generic_socket.h"
#include "ip_socket.h"

#include <string>

class UDPSocket : public IPSocket
{
	public:

		UDPSocket() = delete;
		UDPSocket(const UDPSocket &) = delete;

		UDPSocket(bool verbose, bool debug);
		virtual ~UDPSocket() noexcept;

		void send(const std::string &data, int timeout = -1) const;
		void receive(std::string &data, int timeout = -1) const;
		void connect(std::string host, std::string service, int timeout = -1);
};
