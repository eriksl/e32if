#pragma once

#include "generic_socket.h"

#include <string>
#include <netinet/in.h>

class IPSocket : public GenericSocket
{
	public:

		IPSocket() = delete;
		IPSocket(const IPSocket &) = delete;

		IPSocket(bool verbose, bool debug);
		virtual ~IPSocket();

	protected:

		void _connect(int timeout);
		void _disconnect();
		void _reconnect(int timeout);
		void _send(const std::string &data, int timeout) const;
		void _receive(std::string &data, int timeout) const;
		void _drain(int timeout) const;

		virtual void __connect(int timeout) = 0;
		virtual void __disconnect() = 0;
		virtual void __reconnect(int timeout) = 0;
		virtual void __send(const std::string &data) const = 0;
		virtual void __receive(std::string &data) const = 0;

		struct sockaddr_in6 saddr;
};
