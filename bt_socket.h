#ifndef _bt_socket_h_
#define _bt_socket_h_

#include "e32ifconfig.h"
#include "generic_socket.h"

#include <string>
#include <bluetooth/bluetooth.h>

class BTSocket : GenericSocket
{
	friend class E32If;
	friend class Util;

	protected:

		BTSocket(const E32IfConfig &);
		~BTSocket() noexcept;

		BTSocket() = delete;
		BTSocket(const BTSocket &) = delete;

		bool send(std::string &data, int timeout = -1) const;
		bool receive(std::string &data, int timeout = -1, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		void drain() const;
		void connect(int timeout = -1);
		void disconnect() noexcept;

	private:

		void ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const;
};
#endif
