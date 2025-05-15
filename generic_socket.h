#pragma once

#include <string>
#include <stdint.h>

class GenericSocket
{
	public:

		GenericSocket(bool verbose, bool debug);
		virtual ~GenericSocket();

		GenericSocket() = delete;
		GenericSocket(const GenericSocket &) = delete;

		void connect(std::string host, std::string service = "", int timeout = -1);
		void disconnect();
		void reconnect(int timeout = -1);
		void change_mtu(unsigned int mtu, int timeout);
		void send(const std::string &data, const int timeout = -1) const;
		void receive(std::string &data, const int timeout = -1) const;
		void drain(int timeout) const;

	protected:

		std::string host;
		std::string service;
		int socket_fd;
		bool verbose;
		bool debug;
		unsigned int mtu;

		virtual void _connect(int timeout) = 0;
		virtual void _disconnect() = 0;
		virtual void _reconnect(int timeout) = 0;
		virtual void _change_mtu(int timeout) = 0;
		virtual void _send(const std::string &data, int timeout) const = 0;
		virtual void _receive(std::string &data, int timeout = -1) const = 0;
		virtual void _drain(int timeout) const = 0;
};
