#include "generic_socket.h"
#include "bt_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

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

static const char ble_att_mtu_request[] =						{ BLE_ATT_OP_MTU_REQ,	0x00, 0x04 };
static const char ble_att_mtu_response[] =						{ BLE_ATT_OP_MTU_RSP,	0x00, 0x04 };
static const char ble_att_indication_register_16_request[] =	{ BLE_ATT_OP_WRITE_REQ, 0x11, 0x00, 0x01, 0x00 };
static const char ble_att_indication_register_16_response[] =	{ BLE_ATT_OP_WRITE_RSP };
static const char ble_att_write_16_request[] =					{ BLE_ATT_OP_WRITE_REQ, 0x10, 0x00 };
static const char ble_att_write_16_response[] =					{ BLE_ATT_OP_WRITE_RSP };
static const char ble_att_indication_16_request[] =				{ BLE_ATT_OP_INDICATE_REQ, 0x10, 0x00 };
static const char ble_att_indication_16_response[] =			{ BLE_ATT_OP_INDICATE_RSP };

BTSocket::BTSocket(const EspifConfig &config_in) :
	GenericSocket(config_in)
{
}

BTSocket::~BTSocket() noexcept
{
}

void BTSocket::ble_att_action(const char *tag, const char *request, unsigned int request_length, const char *response, unsigned int response_size) const
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
		throw(hard_exception("connect failed"));

	ble_att_action("mtu", ble_att_mtu_request, sizeof(ble_att_mtu_request), ble_att_mtu_response, sizeof(ble_att_mtu_response));
	ble_att_action("indication", ble_att_indication_register_16_request, sizeof(ble_att_indication_register_16_request), ble_att_indication_register_16_response, sizeof(ble_att_indication_register_16_response));

	GenericSocket::connect();
}

void BTSocket::disconnect() noexcept
{
	GenericSocket::disconnect();
}

bool BTSocket::send(std::string &data) const noexcept
{
	struct pollfd pfd;
	int length;
	std::string packet;
	char response[16];

	pfd.fd = socket_fd;
	pfd.events = POLLOUT | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(data.length() == 0)
	{
		if(config.verbose)
			std::cout << "send: empty buffer" << std::endl;
		return(true);
	}

	if(poll(&pfd, 1, 2000) != 1)
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

	packet.assign(ble_att_write_16_request, sizeof(ble_att_write_16_request));
	packet.append(data);

	if((length = ::write(socket_fd, packet.data(), packet.length())) <= 0)
	{
		if(config.verbose)
			std::cout << "send: send error" << std::endl;
		return(false);
	}

	pfd.fd = socket_fd;
	pfd.events = POLLIN | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, 2000) != 1)
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

	if(::read(socket_fd, response, sizeof(response)) != sizeof(ble_att_write_16_response))
	{
		if(config.verbose)
			std::cout << "send: read response error" << std::endl;
		return(false);
	}

	if(memcmp(response, ble_att_write_16_response, sizeof(ble_att_write_16_response)))
	{
		if(config.verbose)
			std::cout << "send: invalid response" << std::endl;
		return(false);
	}

	data.erase(0, length - sizeof(ble_att_write_16_request));

	return(GenericSocket::send(data));
}

bool BTSocket::receive(std::string &data, uint32_t *hostid, std::string *hostname) const
{
	int length;
	char buffer[2 * config.sector_size];
	struct pollfd pfd;

	pfd.fd = socket_fd;
	pfd.events = POLLIN | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, 2000) != 1)
	{
		if(config.verbose)
			std::cout << boost::format("receive: timeout, length: %u") % data.length() << std::endl;
		return(false);
	}

	if(pfd.revents & POLLERR)
	{
		if(config.verbose)
			std::cout << std::endl << "receive: POLLERR" << std::endl;
		return(false);
	}

	if(pfd.revents & POLLHUP)
	{
		if(config.verbose)
			std::cout << std::endl << "receive: POLLHUP" << std::endl;
		return(false);
	}

	if((length = ::read(socket_fd, buffer, sizeof(buffer))) <= 0)
	{
		if(config.verbose)
			std::cout << std::endl << "receive: length <= 0" << std::endl;
		return(false);
	}

	if(length < (int)sizeof(ble_att_indication_16_request))
	{
		if(config.verbose)
			std::cout << std::endl << "receive: length too small" << std::endl;
		return(false);
	}

	if(memcmp(buffer, ble_att_indication_16_request, sizeof(ble_att_indication_16_request)))
	{
		if(config.verbose)
			std::cout << "receive: invalid response" << std::endl;
		return(false);
	}

	data.append(buffer + sizeof(ble_att_indication_16_request), (size_t)length - sizeof(ble_att_indication_16_request));

	pfd.fd = socket_fd;
	pfd.events = POLLOUT | POLLERR | POLLHUP;
	pfd.revents = 0;

	if(poll(&pfd, 1, 2000) != 1)
	{
		if(config.verbose)
			std::cout << boost::format("receive: timeout, length: %u") % data.length() << std::endl;
		return(false);
	}

	if(pfd.revents & POLLERR)
	{
		if(config.verbose)
			std::cout << std::endl << "receive: POLLERR" << std::endl;
		return(false);
	}

	if(pfd.revents & POLLHUP)
	{
		if(config.verbose)
			std::cout << std::endl << "receive: POLLHUP" << std::endl;
		return(false);
	}

	if(::write(socket_fd, ble_att_indication_16_response, sizeof(ble_att_indication_16_response)) != sizeof(ble_att_indication_16_response))
	{
		if(config.verbose)
			std::cout << "receive: send error" << std::endl;
		return(false);
	}

	if(hostid)
		*hostid = 0;

	if(hostname)
		*hostname = "<bt>";

	return(GenericSocket::receive(data, hostid, hostname));
}

void BTSocket::drain() const noexcept
{
	GenericSocket::drain();
}
