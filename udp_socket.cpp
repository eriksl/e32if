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

UDPSocket::UDPSocket(bool verbose_in, bool debug_in) : IPSocket(verbose_in, debug_in)
{
	if(debug)
		std::cerr << "UDPSocket called" << std::endl;
}

UDPSocket::~UDPSocket()
{
	if(debug)
		std::cerr << "~UDPSocket called" << std::endl;
}

void UDPSocket::__connect(int timeout)
{
	struct addrinfo hints;
	struct addrinfo *res = nullptr;
	int option;
	struct sockaddr_in6 saddr;

	(void)timeout;

	if(debug)
		std::cerr << "UDPSocket::__connect called" << std::endl;

	try
	{
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
			throw("resolve failed");

		saddr = *(struct sockaddr_in6 *)res->ai_addr;
		freeaddrinfo(res);

		if((socket_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
			throw("socket failed");

		option = IP_PMTUDISC_DONT;

		if(setsockopt(socket_fd, IPPROTO_IP, IP_MTU_DISCOVER, &option, sizeof(option)))
			throw("setsockopt(IP_MTU_DISCOVER) failed");

		if(::connect(socket_fd, (const struct sockaddr *)&saddr, sizeof(saddr)))
			throw("connect failed");
	}
	catch(const char *e)
	{
		throw(hard_exception(std::string("UDPSocket connect: ") + e + ", connecting to " + host));
	}
}

void UDPSocket::__disconnect()
{
	if(debug)
		std::cerr << "UDPSocket::__disconnect called" << std::endl;

	if(socket_fd >= 0)
	{
		close(socket_fd);
		socket_fd = -1;
	}
}

void UDPSocket::__reconnect(int timeout)
{
	(void)timeout;

	if(debug)
		std::cerr << "UDPSocket::__reconnect called" << std::endl;
}

void UDPSocket::__change_mtu(int timeout)
{
	(void)timeout;

	if(debug)
		std::cerr << "UDPSocket::__change_mtu called with mtu: " << this->mtu << std::endl;
}

void UDPSocket::__send(const std::string &data) const
{
	if(debug)
		std::cerr << "UDPSocket::__send called" << std::endl;

	if(::send(socket_fd, data.data(), data.length(), 0) <= 0)
		throw(transient_exception(boost::format("UDPSocket::send failed: %s") % strerror(errno)));
}

void UDPSocket::__receive(std::string &data) const
{
	int length;
	char buffer[2 * 4096];

	if(debug)
		std::cerr << "UDPSocket::__receive called" << std::endl;

	if((length = ::recv(socket_fd, buffer, sizeof(buffer) - 1, 0)) <= 0)
		throw(transient_exception("UDPSocket::receive: recvfrom error"));

	data.append(buffer, (size_t)length);
}
