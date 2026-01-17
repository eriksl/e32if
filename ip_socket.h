#pragma once

#include "generic_socket.h"

#include <string>

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
		void _send(const std::string &data, int timeout) const;
		void _receive(std::string &data, int timeout) const;

		virtual void __connect(int timeout) = 0;
		virtual void __disconnect() = 0;
		virtual void __send(const std::string &data) const = 0;
		virtual void __receive(std::string &data) const = 0;
};
