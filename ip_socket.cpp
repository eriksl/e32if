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

IPSocket::IPSocket(bool verbose, bool debug) : GenericSocket(verbose, debug)
{
	if(debug)
		std::cerr << "IPSocket called" << std::endl;

	memset(&saddr, 0, sizeof(saddr));
}

IPSocket::~IPSocket() noexcept
{
	if(debug)
		std::cerr << "~IPSocket called" << std::endl;
}

void IPSocket::send(const std::string &data, int timeout) const
{
	struct pollfd pfd = { .fd = socket_fd, .events = POLLOUT | POLLERR | POLLHUP, .revents = 0 };

	if(debug)
		std::cerr << "IPSocket::send called" << std::endl;

	GenericSocket::send(data, timeout);

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
}

void IPSocket::receive(std::string &data, int timeout) const
{
	struct pollfd pfd = { .fd = socket_fd, .events = POLLIN | POLLERR | POLLHUP, .revents = 0 };

	if(debug)
		std::cerr << "IPSocket::receive called" << std::endl;

	GenericSocket::receive(data, timeout);

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
}
