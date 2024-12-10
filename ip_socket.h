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
		virtual ~IPSocket() noexcept;

		virtual void send(const std::string &data, int timeout = -1) const = 0;
		virtual void receive(std::string &data, int timeout = -1) const = 0;
		virtual void connect(std::string host, std::string service, int timeout = -1) = 0;

	protected:

		struct sockaddr_in6 saddr;
};
