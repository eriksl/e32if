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
static const uint8_t ble_att_write_request[] =					{ BLE_ATT_OP_WRITE_REQ, 0x10, 0x00 };
static const uint8_t ble_att_write_response[] =					{ BLE_ATT_OP_WRITE_RSP };
static const uint8_t ble_att_indication_request[] =				{ BLE_ATT_OP_INDICATE_REQ, 0x10, 0x00 };
static const uint8_t ble_att_indication_response[] =			{ BLE_ATT_OP_INDICATE_RSP };

BTSocket::BTSocket(const EspifConfig &config_in) :
	GenericSocket(config_in)
{
}

BTSocket::~BTSocket() noexcept
{
}

void BTSocket::ble_att_action(const char *tag, const uint8_t *request, unsigned int request_length, const uint8_t *response, unsigned int response_size) const
{
	char buffer[32];

	//fprintf(stderr, "send request for %s\n", tag);

	if(::write(socket_fd, request, request_length) != request_length)
		throw(hard_exception(boost::format("ble_att_action::write failed: %s") % tag));

	//fprintf(stderr, "receiving response for %s\n", tag);

	if(::read(socket_fd, buffer, sizeof(buffer)) != response_size)
		throw(hard_exception(boost::format("ble_att_action::read failed: %s") % tag));

	if(memcmp(response, buffer, response_size))
		throw(hard_exception(boost::format("ble_att_action::invalid response: %s") % tag));
}

void BTSocket::connect()
{
	struct sockaddr_l2 addr;
	struct bt_security btsec;
	uint8_t mtu_request[3];
	uint8_t mtu_response[3];

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

	GenericSocket::connect();
}

void BTSocket::disconnect() noexcept
{
	GenericSocket::disconnect();
}

bool BTSocket::send(std::string &data) const noexcept
{
	struct pollfd pfd;
	unsigned int chunk, length;
	std::string packet;
	char response[16];
	unsigned int timeout = 2000;

	if((sizeof(packet_header_t) + sizeof(ble_att_write_request) + 512) > mtu_size)
	{
		if(config.verbose)
			std::cout << "send: payload does not fit in mtu size" << std::endl;
		return(false);
	}

	length = data.length();

	pfd.fd = socket_fd;
	pfd.events = POLLOUT | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, timeout) != 1)
	{
		if(config.verbose)
			std::cout << "send: timeout" << std::endl;
		return(false);
	}

	if(pfd.revents & (POLLERR | POLLHUP))
	{
		if(config.verbose)
			std::cout << "send: socket error" << std::endl;
		return(false);
	}

	if((chunk = length) > 512)
		chunk = 512;

	packet.assign((const char *)ble_att_write_request, sizeof(ble_att_write_request));
	packet.append(data.substr(0, chunk));

	if((sent = ::write(socket_fd, packet.data(), packet.length())) <= 0)
	{
		if(config.verbose)
			std::cout << "send: send error" << std::endl;
		return(false);
	}

	pfd.fd = socket_fd;
	pfd.events = POLLIN | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, timeout) != 1)
	{
		if(config.verbose)
			std::cout << "send: timeout" << std::endl;
		return(false);
	}

	if(pfd.revents & (POLLERR | POLLHUP))
	{
		if(config.verbose)
			std::cout << "send: socket error" << std::endl;
		return(false);
	}

	if(::read(socket_fd, response, sizeof(response))) != sizeof(ble_att_write_response)
	{
		if(config.verbose)
			std::cout << "send: read response error" << std::endl;
		return(false);
	}

	if(memcmp(response, ble_att_write_response, sizeof(ble_att_write_response)))
	{
		if(config.verbose)
			std::cout << "send: invalid response" << std::endl;
		return(false);
	}

	if(!GenericSocket::send(data))
		return(false);

	data.erase(0, chunk);

	return(true);
}

bool BTSocket::receive(std::string &data, uint32_t *hostid, std::string *hostname) const
{
	int length;
	char buffer[2 * config.sector_size];
	struct pollfd pfd;
	unsigned int timeout = 2000;

	try
	{
		pfd.fd = socket_fd;
		pfd.events = POLLIN | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, timeout) != 1)
			throw((boost::format("receive: timeout, length: %u") % data.length()).str());

		if(pfd.revents & POLLERR)
			throw(std::string("receive: POLLERR"));

		if(pfd.revents & POLLHUP)
			throw(std::string("receive: POLLHUP"));

		if((length = ::read(socket_fd, buffer, sizeof(buffer))) <= 0)
			throw(std::string("receive: length <= 0"));

		if(length < (int)sizeof(ble_att_indication_request))
			throw(std::string("receive: length too small"));

		if(memcmp(buffer, ble_att_indication_request, sizeof(ble_att_indication_request)))
			throw(std::string("receive: invalid response"));

		data.append(buffer + sizeof(ble_att_indication_request), (size_t)length - sizeof(ble_att_indication_request));

		if(hostid) // FIXME
			*hostid = 0;

		if(hostname) // FIXME
			*hostname = "<bt>";

		pfd.fd = socket_fd;
		pfd.events = POLLOUT | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, timeout) != 1)
			throw(std::string("send ack: timeout"));

		if(pfd.revents & POLLERR)
			throw(std::string("send ack: POLLERR"));

		if(pfd.revents & POLLHUP)
			throw(std::string("send ack: POLLHUP"));

		if(::write(socket_fd, ble_att_indication_response, sizeof(ble_att_indication_response)) != sizeof(ble_att_indication_response))
			throw(std::string("send ack: send error"));
	}
	catch(const std::string &e)
	{
		if(config.verbose)
			std::cout << "receive: " << e << std::endl;
	}
	catch(std::exception &e)
	{
		std::cout << "receive: exception: " << e.what() << std::endl;
	}
	catch(...)
	{
		std::cout << "receive: generic exception" << std::endl;
	}

	return(GenericSocket::receive(data, hostid, hostname));
}

void BTSocket::drain() const noexcept
{
	GenericSocket::drain();
}
