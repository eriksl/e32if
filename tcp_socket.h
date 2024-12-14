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
		virtual ~TCPSocket();

	protected:

		void __connect(int timeout);
		void __disconnect();
		void __reconnect(int timeout);
		void __send(const std::string &data) const;
		void __receive(std::string &data) const;
};
