#include "generic_socket.h"
#include "bt_socket.h"
#include "exception.h"
#include "util.h"
#include "crypt.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

enum
{
	// Don't change this without also changing the ESP firmware (menuconfig).
	// It can't be much larger than this, it's limited by BlueZ (on Linux).
	mtu_size = 560,
};

typedef enum
{
	BLE_ATT_OP_ERROR_RSP = 0x01,
	BLE_ATT_OP_MTU_REQ = 0x02,
	BLE_ATT_OP_MTU_RSP = 0x03,
	BLE_ATT_OP_WRITE_REQ = 0x12,
	BLE_ATT_OP_WRITE_RSP = 0x13,
	BLE_ATT_OP_INDICATE_REQ = 0x1d,
	BLE_ATT_OP_INDICATE_RSP = 0x1e,
} ble_att_t;

static const uint8_t ble_att_indication_register_request[] =	{ BLE_ATT_OP_WRITE_REQ, 0x11, 0x00, 0x01, 0x00 };
static const uint8_t ble_att_indication_register_response[] =	{ BLE_ATT_OP_WRITE_RSP };
static const uint8_t ble_att_value_write_request[] =			{ BLE_ATT_OP_WRITE_REQ, 0x10, 0x00 };
static const uint8_t ble_att_value_write_response[] =			{ BLE_ATT_OP_WRITE_RSP };
static const uint8_t ble_att_value_indication_request[] =		{ BLE_ATT_OP_INDICATE_REQ, 0x10, 0x00 };
static const uint8_t ble_att_value_indication_response[] =		{ BLE_ATT_OP_INDICATE_RSP };

BTSocket::BTSocket(bool verbose_in, bool debug_in) : GenericSocket(verbose_in, debug_in)
{
}

BTSocket::~BTSocket()
{
}

void BTSocket::ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const
{
	char buffer[32];

	if(::send(socket_fd, request, request_length, 0) != request_length)
		throw(transient_exception(boost::format("ble_att_action::write failed: %s") % tag));

	if(::recv(socket_fd, buffer, sizeof(buffer), 0) != response_size)
		throw(transient_exception(boost::format("ble_att_action::read failed: %s") % tag));

	if(memcmp(response, buffer, response_size))
		throw(transient_exception(boost::format("ble_att_action::invalid response: %s") % tag));
}

void BTSocket::_connect(int timeout)
{
	struct sockaddr_l2 addr;
	struct bt_security btsec;
	uint8_t mtu_request[3];
	uint8_t mtu_response[3];
	std::string bt_cmd;

	(void)timeout;

	if(debug)
		std::cerr << "BTSocket::_connect called" << std::endl;

	if((socket_fd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
		throw(hard_exception("socket failed"));

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	addr.l2_bdaddr = {{ 0, 0, 0, 0, 0, 0 }}; // BDADDR_ANY
	addr.l2_cid = htobs(4);
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;

	if(bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)))
		throw(hard_exception("bind failed"));

	memset(&btsec, 0, sizeof(btsec));
	btsec.level = 1;

	if(setsockopt(socket_fd, SOL_BLUETOOTH, BT_SECURITY, &btsec, sizeof(btsec)) != 0)
		throw(hard_exception("set security level failed"));

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(host.c_str(), &addr.l2_bdaddr);
	addr.l2_cid = htobs(4);
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;

	if(::connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)))
	{
		if(verbose)
			perror("connect");
		throw(transient_exception("connect failed"));
	}

	mtu_request[0] = BLE_ATT_OP_MTU_REQ;
	mtu_request[1] = (mtu_size & 0x00ff) >> 0;
	mtu_request[2] = (mtu_size & 0xff00) >> 8;

	mtu_response[0] = BLE_ATT_OP_MTU_RSP;
	mtu_response[1] = (mtu_size & 0x00ff) >> 0;
	mtu_response[2] = (mtu_size & 0xff00) >> 8;

	ble_att_action("mtu", mtu_request, sizeof(mtu_request), mtu_response, sizeof(mtu_response));
	ble_att_action("indication", ble_att_indication_register_request, sizeof(ble_att_indication_register_request),
			ble_att_indication_register_response, sizeof(ble_att_indication_register_response));
}

void BTSocket::_disconnect()
{
	if(debug)
		std::cerr << "BTSocket::_disconnect called" << std::endl;

	if(socket_fd >= 0)
		close(socket_fd);

	socket_fd = -1;
}

void BTSocket::_send(const std::string &data, int timeout) const
{
	struct pollfd pfd;
	std::string encrypted_data;
	std::string packet;
	int length;
	std::string response;

	encrypted_data = Crypt::aes256(true, Crypt::password_to_aes256_key(this->key), data);

	if(debug)
		std::cerr << boost::format("BTSocket::_send(%u) called") % encrypted_data.length() << std::endl;

	packet.assign(reinterpret_cast<const char *>(ble_att_value_write_request), sizeof(ble_att_value_write_request));
	packet.append(encrypted_data);

	pfd.fd = socket_fd;
	pfd.events = POLLOUT | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, timeout) != 1)
		throw(transient_exception("bluetooth send poll timeout"));

	if(pfd.revents & (POLLERR | POLLHUP))
		throw(hard_exception("bluetooth send poll error"));

	if(::send(socket_fd, packet.data(), packet.length(), 0) <= 0)
		throw(hard_exception("bluetooth send error"));

	pfd.fd = socket_fd;
	pfd.events = POLLIN | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, timeout) != 1)
		throw(transient_exception("bluetooth send receive ack timeout"));

	response.resize(1024);

	if((length = ::recv(socket_fd, response.data(), response.size(), 0)) != sizeof(ble_att_value_write_response))
		throw(hard_exception(boost::format("bluetooth send receive ack error: %d") % length));

	if(response.compare(0, sizeof(ble_att_value_write_response), reinterpret_cast<const char *>(ble_att_value_write_response), sizeof(ble_att_value_write_response)))
		throw(hard_exception("bluetooth send receive ack: invalid response"));
}

void BTSocket::_receive(std::string &data, int timeout) const
{
	struct pollfd pfd;
	int length;
	std::string encrypted_data;

	if(debug)
		std::cerr << "BTSocket::_receive called" << std::endl;

	length = 0;

	pfd.fd = socket_fd;
	pfd.events = POLLIN | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, timeout) != 1)
		throw(transient_exception("bluetooth receive timeout"));

	if(pfd.revents & (POLLERR | POLLHUP))
		throw(hard_exception("bluetooth receive poll error"));

	encrypted_data.resize(1024);

	if((length = ::recv(socket_fd, encrypted_data.data(), encrypted_data.size(), 0)) <= 0)
		throw(hard_exception("bluetooth receive error"));

	encrypted_data.resize(length);

	if(encrypted_data.size() < sizeof(ble_att_value_indication_request))
		throw(hard_exception("bluetooth receive indication error"));

	if(encrypted_data.compare(0, sizeof(ble_att_value_indication_request), reinterpret_cast<const char *>(ble_att_value_indication_request),
				sizeof(ble_att_value_indication_request)))
		throw(hard_exception("bluetooth receive invalid response"));

	encrypted_data.erase(encrypted_data.begin(), encrypted_data.begin() + sizeof(ble_att_value_indication_request));

	pfd.fd = socket_fd;
	pfd.events = POLLOUT | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, timeout) != 1)
		throw(hard_exception("bluetooth receive send ack timeout"));

	if(pfd.revents & (POLLERR | POLLHUP))
		throw(hard_exception("bluetooth receive send ack poll error"));

	if(::send(socket_fd, ble_att_value_indication_response, sizeof(ble_att_value_indication_response), 0) != sizeof(ble_att_value_indication_response))
		throw(hard_exception("bluetooth receive send ack send error"));

	data = Crypt::aes256(false, Crypt::password_to_aes256_key(this->key), encrypted_data);
}
