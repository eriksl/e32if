#include "generic_socket.h"
#include "ip_socket.h"
#include "exception.h"
#include "packet.h"

#include <unistd.h>
#include <poll.h>
#include <iostream>

#include <string>

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
			throw(" poll timeout");
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("IPSocket::send: %s (%s)") % e % strerror(errno)));
	}

	this->__send(data);
}

void IPSocket::_receive(std::string &data, int timeout) const
{
	std::string segment;
	struct pollfd pfd = { .fd = socket_fd, .events = POLLIN | POLLERR | POLLHUP, .revents = 0 };

	if(debug)
		std::cerr << "IPSocket::_receive called" << std::endl;

	try
	{
		for(;;)
		{
			if(pfd.revents & (POLLERR | POLLHUP))
				throw("receive poll error");

			if(poll(&pfd, 1, timeout) != 1)
				throw(transient_exception("IPSocket::receive: poll timeout"));

			this->__receive(segment);
			data.append(segment);

			if(!Packet::valid(data)) // FIXME telnet unpacketised
				throw("IPSocket::invalid packet");

			if(Packet::complete(data))
				return;
		}
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("IPSocket::receive: %s (%s)") % e % strerror(errno)));
	}
}
