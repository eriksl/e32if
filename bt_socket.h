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
		~BTSocket() noexcept;


		void send(const std::string &data, int timeout = -1) const;
		void receive(std::string &data, int timeout = -1) const;
		void connect(std::string host, std::string service, int timeout = -1);
		void disconnect() noexcept;

	private:

		void ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const;
};
