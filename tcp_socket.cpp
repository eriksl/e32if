#include "generic_socket.h"
#include "tcp_socket.h"
#include "util.h"
#include "exception.h"

#include <string>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>
#include <netinet/tcp.h>

TCPSocket::TCPSocket(bool verbose, bool debug) : IPSocket(verbose, debug)
{
	if(debug)
		std::cerr << "TCPSocket called" << std::endl;
}

TCPSocket::~TCPSocket()
{
	if(debug)
		std::cerr << "~TCPSocket called" << std::endl;
}

void TCPSocket::connect(std::string host_in, std::string service_in, int timeout)
{
	struct addrinfo hints;
	struct addrinfo *res = nullptr;
	struct pollfd pfd;
	int option;

	if(debug)
		std::cerr << "TCPSocket::connect called" << std::endl;

	GenericSocket::connect(host_in, service_in, timeout);

	try
	{
		if((socket_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
			throw("socket failed");

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
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

		pfd.fd = socket_fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;

		if((::connect(socket_fd, (const struct sockaddr *)&saddr, sizeof(saddr))) && (errno != EINPROGRESS))
			throw("connect failed");

		if(poll(&pfd, 1, timeout) != 1)
			throw("connect timeout");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("connect poll error");

		if(!(pfd.revents & POLLOUT))
			throw("connect poll unfinished");

		option = 0;

		if(setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option)))
			throw("setsockopt(TCP_NODELAY) failed");
	}
	catch(const char *e)
	{
		throw(hard_exception(std::string("TCPSocket connect: ") + e + ", connecting to " + host));
	}
}

void TCPSocket::send(const std::string &data, int timeout) const
{
	if(debug)
		std::cerr << "TCPSocket::send called" << std::endl;

	IPSocket::send(data, timeout);

	if(::send(socket_fd, data.data(), data.length(), 0) <= 0)
		throw(hard_exception(boost::format("TCPSocket::send: %s") % strerror(errno)));
}

void TCPSocket::receive(std::string &data, int timeout) const
{
	int length;
	char buffer[2 * 4096];

	if(debug)
		std::cerr << "TCPSocket::receive called" << std::endl;

	IPSocket::receive(data, timeout);

	if((length = ::recv(socket_fd, buffer, sizeof(buffer) - 1, 0)) <= 0)
		throw(hard_exception("TCPSocket::receive: receive error"));

	data.append(buffer, (size_t)length);
}