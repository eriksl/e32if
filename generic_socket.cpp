#include "generic_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>

GenericSocket::GenericSocket(const E32IfConfig &config_in) : config(config_in)
{
	socket_fd = -1;
}

GenericSocket::~GenericSocket() noexcept
{
	this->disconnect();
}

void GenericSocket::connect(int timeout)
{
	(void)timeout;
	throw(hard_exception("GenericSocket::connect called"));
}

void GenericSocket::disconnect() noexcept
{
	if(socket_fd >= 0)
		close(socket_fd);

	socket_fd = -1;
}

bool GenericSocket::send(std::string &data, int timeout) const
{
	(void)data;
	(void)timeout;
	throw(hard_exception("GenericSocket::send called"));
}

bool GenericSocket::receive(std::string &data, int timeout, uint32_t *hostid, std::string *hostname) const
{
	(void)data;
	(void)timeout;
	(void)hostid;
	(void)hostname;
	throw(hard_exception("GenericSocket::receive called"));
}

void GenericSocket::drain() const
{
	throw(hard_exception("GenericSocket::drain called"));
}
