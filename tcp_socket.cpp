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

TCPSocket::TCPSocket(bool verbose_in, bool debug_in) : IPSocket(verbose_in, debug_in)
{
	if(debug)
		std::cerr << "TCPSocket called" << std::endl;
}

TCPSocket::~TCPSocket()
{
	if(debug)
		std::cerr << "~TCPSocket called" << std::endl;
}

void TCPSocket::__connect(int timeout)
{
	struct addrinfo hints;
	struct addrinfo *res = nullptr;
	struct pollfd pfd;
	int option;

	if(debug)
		std::cerr << "TCPSocket::__connect called" << std::endl;

	try
	{
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

		if((socket_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
			throw("socket failed");

		if(debug)
			std::cerr << boost::format("socket fd: %d\n") % socket_fd;

		option = this->mtu_value;

		if(setsockopt(socket_fd, IPPROTO_TCP, TCP_MAXSEG, &option, sizeof(option)))
			throw("setsockopt(TCP_MAXSEG) failed");

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
	}
	catch(const char *e)
	{
		throw(hard_exception(std::string("TCPSocket connect: ") + e + ", connecting to " + host));
	}
}

void TCPSocket::__disconnect()
{
	if(debug)
		std::cerr << "TCPSocket::__disconnect called" << std::endl;

	if(socket_fd >= 0)
		close(socket_fd);

	socket_fd = -1;
}

void TCPSocket::__reconnect(int timeout)
{
	if(debug)
		std::cerr << "TCPSocket::__reconnect called" << std::endl;

	this->__disconnect();
	this->__connect(timeout);
}

void TCPSocket::__send(const std::string &data) const
{
	if(debug)
		std::cerr << "TCPSocket::__send called" << std::endl;

	if(::send(socket_fd, data.data(), data.length(), 0) <= 0)
		throw(hard_exception(boost::format("TCPSocket::send: %s") % strerror(errno)));
}

void TCPSocket::__receive(std::string &data) const
{
	int length;
	char buffer[2 * 4096];

	if(debug)
		std::cerr << "TCPSocket::__receive called" << std::endl;

	if((length = ::recv(socket_fd, buffer, sizeof(buffer) - 1, 0)) <= 0)
		throw(hard_exception(boost::format("TCPSocket::receive: receive error: %d") % length));

	if(debug)
		std::cerr << boost::format("received %d bytes by tcp\n") % length;

	data.append(buffer, (size_t)length);
}
