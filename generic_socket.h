#ifndef _generic_socket_h_
#define _generic_socket_h_

#include "espifconfig.h"

#include <string>
#include <stdint.h>

class GenericSocket
{
	friend class Espif;
	friend class Util;

	protected:

		GenericSocket(const EspifConfig &);
		virtual ~GenericSocket() noexcept;

		GenericSocket() = delete;
		GenericSocket(const GenericSocket &) = delete;

		virtual void connect();
		virtual void disconnect() noexcept;

		virtual bool send(std::string &data, int timeout = 500) const noexcept;
		virtual bool receive(std::string &data, int timeout = 500, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		virtual void drain(int timeout = 500) const noexcept;

		int socket_fd;
		const EspifConfig config;
};
#endif
