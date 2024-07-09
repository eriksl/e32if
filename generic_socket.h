#pragma once

#include "e32_config.h"

#include <string>
#include <stdint.h>

class GenericSocket
{
	public:

		GenericSocket(const e32_config &);
		virtual ~GenericSocket() noexcept;

		GenericSocket() = delete;
		GenericSocket(const GenericSocket &) = delete;

		virtual void connect(int timeout = -1);
		virtual void disconnect() noexcept;

		virtual bool send(std::string &data, int timeout = -1) const;
		virtual bool receive(std::string &data, int timeout = -1, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		virtual void drain() const;

	protected:

		int socket_fd;
		const e32_config config;
};
