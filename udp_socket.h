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
		virtual ~UDPSocket();

	protected:

		void __connect(int timeout);
		void __disconnect();
		void __reconnect(int timeout);
		void __change_mtu(int timeout);
		void __send(const std::string &data) const;
		void __receive(std::string &data) const;
};
