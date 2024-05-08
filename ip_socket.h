#ifndef _ip_socket_h_
#define _ip_socket_h_

#include "espifconfig.h"
#include "generic_socket.h"

#include <string>

#include <netinet/in.h>

class IPSocket : GenericSocket
{
	friend class Espif;
	friend class Util;

	protected:

		IPSocket(const EspifConfig &);
		~IPSocket() noexcept;

		IPSocket() = delete;
		IPSocket(const IPSocket &) = delete;

		bool send(std::string &data, int timeout = 500) const noexcept;
		bool receive(std::string &data, int timeout = 500, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		void drain(int timeout = 500) const noexcept;
		void connect();
		void disconnect() noexcept;

	private:

		struct sockaddr_in saddr;
};
#endif
