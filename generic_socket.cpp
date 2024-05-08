#include "generic_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>

GenericSocket::GenericSocket(const EspifConfig &config_in) : config(config_in)
{
	socket_fd = -1;
}

GenericSocket::~GenericSocket() noexcept
{
	this->disconnect();
}

void GenericSocket::connect()
{
}

void GenericSocket::disconnect() noexcept
{
	if(socket_fd >= 0)
		close(socket_fd);

	socket_fd = -1;
}

bool GenericSocket::send(std::string &data) const noexcept
{
	(void)data;
	return(true);
}

bool GenericSocket::receive(std::string &data, uint32_t *hostid, std::string *hostname) const
{
	(void)data;
	(void)hostid;
	(void)hostname;
	return(true);
}

void GenericSocket::drain() const noexcept
{
}
