#pragma once

#include "generic_socket.h"

#include <string>
#include <bluetooth/bluetooth.h>

class BTSocket : public GenericSocket
{
	public:

		BTSocket() = delete;
		BTSocket(const BTSocket &) = delete;

		BTSocket(bool verbose, bool debug);
		virtual ~BTSocket();

	protected:

		void _connect(int timeout);
		void _disconnect();
		void _reconnect(int timeout);
		void _change_mtu(int timeout);
		void _send(const std::string &data, int timeout) const;
		void _receive(std::string &data, int timeout) const;
		void _drain(int timeout) const;

	private:

		void ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const;
};
