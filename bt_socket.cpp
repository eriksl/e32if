#include "generic_socket.h"
#include "bt_socket.h"
#include "util.h"
#include "exception.h"
#include "packet.h"

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
static const uint8_t ble_att_value_key_request[] =				{ BLE_ATT_OP_WRITE_REQ, 0x13, 0x00 };
static const uint8_t ble_att_value_key_response[] =				{ BLE_ATT_OP_WRITE_RSP };

BTSocket::BTSocket(const E32IfConfig &config_in) :
	GenericSocket(config_in)
{
}

BTSocket::~BTSocket() noexcept
{
}

void BTSocket::ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const
{
	char buffer[32];

	if(::send(socket_fd, request, request_length, 0) != request_length)
		throw(hard_exception(boost::format("ble_att_action::write failed: %s") % tag));

	if(::recv(socket_fd, buffer, sizeof(buffer), 0) != response_size)
		throw(hard_exception(boost::format("ble_att_action::read failed: %s") % tag));

	if(memcmp(response, buffer, response_size))
		throw(hard_exception(boost::format("ble_att_action::invalid response: %s") % tag));
}

void BTSocket::connect(int timeout)
{
	struct sockaddr_l2 addr;
	struct bt_security btsec;
	uint8_t mtu_request[3];
	uint8_t mtu_response[3];
	std::string key;
	std::string bt_cmd;
	std::string encrypted_key;

	(void)timeout;

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
	btsec.level = 3;

	if(setsockopt(socket_fd, SOL_BLUETOOTH, BT_SECURITY, &btsec, sizeof(btsec)) != 0)
		throw(hard_exception("set security level failed"));

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(config.host.c_str(), &addr.l2_bdaddr);
	addr.l2_cid = htobs(4);
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;

	if(::connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)))
	{
		if(config.verbose)
			perror("connect");
		throw(hard_exception("connect failed"));
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

	key.append(1, addr.l2_bdaddr.b[0] ^ 0x55);
	key.append(1, addr.l2_bdaddr.b[1] ^ 0x55);
	key.append(1, addr.l2_bdaddr.b[2] ^ 0x55);
	key.append(1, addr.l2_bdaddr.b[3] ^ 0x55);
	key.append(1, addr.l2_bdaddr.b[4] ^ 0x55);
	key.append(1, addr.l2_bdaddr.b[5] ^ 0x55);
	key.append(1, addr.l2_bdaddr.b[5] ^ 0xaa);
	key.append(1, addr.l2_bdaddr.b[4] ^ 0xaa);
	key.append(1, addr.l2_bdaddr.b[3] ^ 0xaa);
	key.append(1, addr.l2_bdaddr.b[2] ^ 0xaa);
	key.append(1, addr.l2_bdaddr.b[1] ^ 0xaa);
	key.append(1, addr.l2_bdaddr.b[0] ^ 0xaa);

	encrypted_key = Util::encrypt_aes_256(key);

	bt_cmd.assign((const char *)ble_att_value_key_request, sizeof(ble_att_value_key_request));
	bt_cmd.append(encrypted_key);

	ble_att_action("key", (const uint8_t *)bt_cmd.data(), bt_cmd.length(), ble_att_value_key_response, sizeof(ble_att_value_key_response));
}

void BTSocket::disconnect() noexcept
{
	GenericSocket::disconnect();
}

bool BTSocket::send(std::string &data, int timeout) const
{
	struct pollfd pfd;
	unsigned int chunk;
	std::string packet;
	char response[16];

	if(timeout < 0)
		timeout = 2000;

	if((chunk = data.length()) > 512)
		chunk = 512;

	packet.assign((const char *)ble_att_value_write_request, sizeof(ble_att_value_write_request));
	packet.append(data.substr(0, chunk));

	try
	{
		if((sizeof(packet_header_t) + sizeof(ble_att_value_write_request) + 512) > mtu_size)
			throw("payload does not fit in mtu size");

		pfd.fd = socket_fd;
		pfd.events = POLLOUT | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, timeout) != 1)
			throw("send poll timeout");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("send poll error");

		if(::send(socket_fd, packet.data(), packet.length(), 0) <= 0)
			throw("send error");

		pfd.fd = socket_fd;
		pfd.events = POLLIN | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, timeout) != 1)
			throw("receive poll timeout");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("receive poll error");

		if(::recv(socket_fd, response, sizeof(response), 0) != sizeof(ble_att_value_write_response))
			throw("receive response error");

		if(memcmp(response, ble_att_value_write_response, sizeof(ble_att_value_write_response)))
			throw("receive response invalid");
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("btsocket::send: %s (%s)") % e % strerror(errno)));
	}

	data.erase(0, chunk);

	return(data.length() == 0);
}

bool BTSocket::receive(std::string &data, int timeout, uint32_t *hostid, std::string *hostname) const
{
	int length;
	char buffer[2 * config.sector_size];
	struct pollfd pfd;

	if(timeout < 0)
		timeout = 10000;

	try
	{
		pfd.fd = socket_fd;
		pfd.events = POLLIN | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, timeout) != 1)
			throw("receive poll timeout");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("receive poll error");

		if((length = ::recv(socket_fd, buffer, sizeof(buffer), 0)) <= 0)
			throw("receive error");

		if(length < (int)sizeof(ble_att_value_indication_request))
			throw("receive indication error");

		if(memcmp(buffer, ble_att_value_indication_request, sizeof(ble_att_value_indication_request)))
			throw("receive invalid response");

		data.append(buffer + sizeof(ble_att_value_indication_request), (size_t)length - sizeof(ble_att_value_indication_request));

		if(hostid) // FIXME
			*hostid = 0;

		if(hostname) // FIXME
			*hostname = "<bt>";

		pfd.fd = socket_fd;
		pfd.events = POLLOUT | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, timeout) != 1)
			throw("send ack timeout");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("send ack error");

		if(::send(socket_fd, ble_att_value_indication_response, sizeof(ble_att_value_indication_response), 0) != sizeof(ble_att_value_indication_response))
			throw("send ack send error");
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("btsocket::receive: %s (%s)") % e % strerror(errno)));
	}

	return(length < 552); /* non-fragmented chunk or final, incomplete chunk, sync this value with the esp32 firmware */
}

void BTSocket::drain() const
{
}
