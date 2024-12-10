#include "generic_socket.h"
#include "udp_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>
#include <netinet/tcp.h>

UDPSocket::UDPSocket(bool verbose, bool debug) : IPSocket(verbose, debug)
{
	if(debug)
		std::cerr << "UDPSocket called" << std::endl;
}

UDPSocket::~UDPSocket()
{
	if(debug)
		std::cerr << "~UDPSocket called" << std::endl;
}

void UDPSocket::connect(std::string host_in, std::string service_in, int timeout)
{
	struct addrinfo hints;
	struct addrinfo *res = nullptr;

	if(debug)
		std::cerr << "UDPSocket::connect called" << std::endl;

	GenericSocket::connect(host_in, service_in, timeout);

	try
	{
		if((socket_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
			throw("socket failed");

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICSERV;

		if(getaddrinfo(host.c_str(), service.c_str(), &hints, &res))
		{
			if(res)
				freeaddrinfo(res);
			throw("unknown host");
		}

		if(!res || !res->ai_addr)
			throw("resolve error");

		saddr = *(struct sockaddr_in6 *)res->ai_addr;
		freeaddrinfo(res);
	}
	catch(const char *e)
	{
		throw(hard_exception(std::string("UDPSocket connect: ") + e + ", connecting to " + host));
	}
}

void UDPSocket::send(const std::string &data, int timeout) const
{
	if(debug)
		std::cerr << "UDPSocket::send called" << std::endl;

	IPSocket::send(data, timeout);

	if(::sendto(socket_fd, data.data(), data.length(), 0, (const struct sockaddr *)&this->saddr, sizeof(this->saddr)) <= 0)
		throw(hard_exception(boost::format("IPSocket::send failed: %s") % strerror(errno)));
}

void UDPSocket::receive(std::string &data, int timeout) const
{
	int length;
	char buffer[2 * 4096];

	(void)timeout;

	if(debug)
		std::cerr << "UDPSocket::receive called" << std::endl;

	IPSocket::receive(data, timeout);

	if((length = ::recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0, nullptr, 0)) <= 0)
		throw(hard_exception("UDPSocket::receive: recvfrom error"));

	data.append(buffer, (size_t)length);
}
