#pragma once

#include "generic_socket.h"
#include "ip_socket.h"

#include <string>

class TCPSocket : public IPSocket
{
	public:

		TCPSocket() = delete;
		TCPSocket(const TCPSocket &) = delete;

		TCPSocket(bool verbose, bool debug);
		virtual ~TCPSocket() noexcept;

		void send(const std::string &data, int timeout = -1) const;
		void receive(std::string &data, int timeout = -1) const;
		void connect(std::string host, std::string service, int timeout = -1);
};
