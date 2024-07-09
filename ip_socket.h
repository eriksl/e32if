#pragma once

#include "e32_config.h"
#include "generic_socket.h"

#include <string>
#include <netinet/in.h>

class IPSocket : public GenericSocket
{
	public:

		IPSocket(const e32_config &);
		~IPSocket() noexcept;

		IPSocket() = delete;
		IPSocket(const IPSocket &) = delete;

		bool send(std::string &data, int timeout = -1) const;
		bool receive(std::string &data, int timeout = -1, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		void drain() const;
		void connect(int timeout = -1);
		void disconnect() noexcept;

	private:

		struct sockaddr_in saddr;
};
