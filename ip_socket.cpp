#include "generic_socket.h"
#include "ip_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>
#include <netinet/tcp.h>

IPSocket::IPSocket(bool verbose_in, bool debug_in) : GenericSocket(verbose_in, debug_in)
{
	if(debug)
		std::cerr << "IPSocket called" << std::endl;
}

IPSocket::~IPSocket()
{
	if(debug)
		std::cerr << "~IPSocket called" << std::endl;
}

void IPSocket::_connect(int timeout)
{
	if(debug)
		std::cerr << "IPSocket::_connect called" << std::endl;

	this->__connect(timeout);
}

void IPSocket::_disconnect()
{
	if(debug)
		std::cerr << "IPSocket::_disconnect called" << std::endl;

	this->__disconnect();
}

void IPSocket::_reconnect(int timeout)
{
	if(debug)
		std::cerr << "IPSocket::_reconnect called" << std::endl;

	this->__reconnect(timeout);
}

void IPSocket::_change_mtu(int timeout)
{
	if(debug)
		std::cerr << "IPSocket::_change_mtu called" << std::endl;

	this->__change_mtu(timeout);
}

void IPSocket::_send(const std::string &data, int timeout) const
{
	struct pollfd pfd = { .fd = socket_fd, .events = POLLOUT | POLLERR | POLLHUP, .revents = 0 };

	if(debug)
		std::cerr << "IPSocket::_send called: " << data.length() << std::endl;

	try
	{
		if(data.length() == 0)
			throw("empty_buffer");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("poll error");

		if(poll(&pfd, 1, timeout) != 1)
			throw(transient_exception("IPSocket::send: poll timeout"));
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("IPSocket::send: %s (%s)") % e % strerror(errno)));
	}

	this->__send(data);
}

void IPSocket::_receive(std::string &data, int timeout) const
{
	struct pollfd pfd = { .fd = socket_fd, .events = POLLIN | POLLERR | POLLHUP, .revents = 0 };

	if(debug)
		std::cerr << "IPSocket::_receive called" << std::endl;

	try
	{
		if(pfd.revents & (POLLERR | POLLHUP))
			throw("receive poll error");

		if(poll(&pfd, 1, timeout) != 1)
			throw(transient_exception("IPSocket::receive: poll timeout"));
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("IPSocket::receive: %s (%s)") % e % strerror(errno)));
	}

	this->__receive(data);
}

void IPSocket::_drain(int timeout) const
{
	std::string data;
	unsigned int packet = 0;
	enum { drain_packets = 4 };

	if(debug)
		std::cerr << "IPSocket::_drain called" << std::endl;

	if(verbose)
		std::cerr << "draining..." << std::endl;

	for(packet = 0; packet < drain_packets; packet++)
	{
		try
		{
			this->_receive(data, timeout);
		}
		catch(const transient_exception &e)
		{
			break;
		}
	}

	if(verbose)
		std::cerr << (boost::format("drained %u bytes in %u chunks") % data.length() % packet).str() << std::endl;
}
