#pragma once

#include <string>
#include <stdint.h>

class GenericSocket
{
	public:

		GenericSocket(bool verbose, bool debug);
		virtual ~GenericSocket() noexcept;

		GenericSocket() = delete;
		GenericSocket(const GenericSocket &) = delete;

		void mtu(unsigned int mtu);
		unsigned int mtu(void) noexcept;

		virtual void connect(std::string host, std::string service = "", int timeout = -1);
		void disconnect() noexcept;
		void reconnect(int timeout = -1);

		virtual void send(const std::string &data, int timeout = -1) const = 0;
		virtual void receive(std::string &data, int timeout = -1) const = 0;
		virtual void drain(unsigned int timeout) const;

	protected:

		std::string host;
		std::string service;
		int mtu_value;
		int socket_fd;
		bool verbose;
		bool debug;
};
