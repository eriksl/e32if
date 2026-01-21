#include "generic_socket.h"

#include <unistd.h>

#include <string>
#include <iostream>

GenericSocket::GenericSocket(bool verbose_in, bool debug_in) : host(""), service(""), socket_fd(-1), verbose(verbose_in), debug(debug_in)
{
	if(debug)
		std::cerr << "GenericSocket called" << std::endl;
}

GenericSocket::~GenericSocket()
{
	if(debug)
		std::cerr << "~GenericSocket called" << std::endl;

	if(socket_fd >= 0)
		::close(socket_fd);
}

void GenericSocket::connect(std::string_view host_in, std::string_view service_in, std::string_view key_in, int timeout)
{
	if(debug)
		std::cerr << "GenericSocket::connect called" << std::endl;

	if(!host_in.empty())
		host = host_in;

	if(!service_in.empty())
		service = service_in;

	if(!key_in.empty())
		key = key_in;

	this->_connect(timeout);
}

void GenericSocket::disconnect()
{
	if(debug)
		std::cerr << "GenericSocket::disconnect called" << std::endl;

	this->_disconnect();
}

void GenericSocket::send(const std::string &data, const int timeout) const
{
	if(debug)
		std::cerr << "GenericSocket::send called: " << data.length() << std::endl;

	this->_send(data, timeout);
}

void GenericSocket::receive(std::string &data, const int timeout) const
{
	if(debug)
		std::cerr << "GenericSocket::receive called" << std::endl;

	data.clear();

	this->_receive(data, timeout);
}
