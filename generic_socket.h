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

		virtual bool send(std::string &data) const;
		virtual bool receive(std::string &data, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		virtual void drain() const;

		int socket_fd;
		const EspifConfig config;
};
#endif
