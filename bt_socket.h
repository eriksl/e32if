#pragma once

#include "e32_config.h"
#include "generic_socket.h"

#include <string>
#include <bluetooth/bluetooth.h>

class BTSocket : public GenericSocket
{
	public:

		BTSocket(const e32_config &);
		~BTSocket() noexcept;

		BTSocket() = delete;
		BTSocket(const BTSocket &) = delete;

		void send(const std::string &data, int timeout = -1) const;
		void receive(std::string &data, int timeout = -1, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		void drain() const;
		void connect(int timeout = -1);
		void disconnect() noexcept;

	private:

		void ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const;
};
