#ifndef _bt_socket_h_
#define _bt_socket_h_

#include "espifconfig.h"
#include "generic_socket.h"

#include <string>

#include <netinet/in.h>
#include <bluetooth/bluetooth.h>
//#include <bluetooth/l2cap.h>

class BTSocket : GenericSocket
{
	friend class Espif;
	friend class Util;

	protected:

		BTSocket(const EspifConfig &);
		~BTSocket() noexcept;

		BTSocket() = delete;
		BTSocket(const BTSocket &) = delete;

		bool send(std::string &data) const noexcept;
		bool receive(std::string &data, uint32_t *hostid = nullptr, std::string *hostname = nullptr) const;
		void drain() const noexcept;
		void connect();
		void disconnect() noexcept;

	private:

		void ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const;
};
#endif
