#include "generic_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>

enum
{
	fallback_mtu = 512,
};

GenericSocket::GenericSocket(bool verbose_in, bool debug_in) : host(""), service(""), mtu_value(fallback_mtu), socket_fd(-1), verbose(verbose_in), debug(debug_in)
{
	if(debug)
		std::cerr << "GenericSocket called" << std::endl;
}

GenericSocket::~GenericSocket()
{
	if(debug)
		std::cerr << "~GenericSocket called" << std::endl;

	if(socket_fd >= 0)
		close(socket_fd);
}

void GenericSocket::connect(std::string host_in, std::string service_in, int timeout)
{
	if(debug)
		std::cerr << "GenericSocket::connect called" << std::endl;

	host = host_in;
	service = service_in;

	this->_connect(timeout);
}

void GenericSocket::disconnect()
{
	if(debug)
		std::cerr << "GenericSocket::disconnect called" << std::endl;

	this->_disconnect();
}

void GenericSocket::reconnect(int timeout)
{
	if(debug)
		std::cerr << "GenericSocket::reconnect called" << std::endl;

	this->_reconnect(timeout);
}

void GenericSocket::mtu(unsigned int mtu)
{
	if(mtu < 128)
		throw(hard_exception("GenericSocket::mtu mtu value too small"));

	if(mtu > 4096)
		throw(hard_exception("GenericSocket::mtu mtu value too large"));

	this->mtu_value = mtu;
}

unsigned int GenericSocket::mtu(void) noexcept
{
	return(this->mtu_value);
}

void GenericSocket::send(const std::string &data, int timeout) const
{
	if(debug)
		std::cerr << "GenericSocket::send called" << std::endl;

	this->_send(data, timeout);
}

void GenericSocket::receive(std::string &data, int timeout) const
{
	if(debug)
		std::cerr << "GenericSocket::receive called" << std::endl;

	data.clear();

	this->_receive(data, timeout);
}

void GenericSocket::drain(int timeout) const
{
	if(debug)
		std::cerr << "GenericSocket::drain called" << std::endl;

	this->_drain(timeout);
}
