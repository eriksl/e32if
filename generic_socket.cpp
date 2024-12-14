#include "generic_socket.h"
#include "util.h"
#include "exception.h"
#include "packet.h"

#include <string.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>

#include <string>
#include <iostream>
#include <boost/format.hpp>

enum
{
	fallback_mtu = 512,
	min_chunk_size = 128,
	max_chunk_size = 4096,
	extra_chunk_size = sizeof(packet_header_t) + 32,
};

GenericSocket::GenericSocket(bool verbose_in, bool debug_in) : host(""), service(""), socket_fd(-1), verbose(verbose_in), debug(debug_in), mtu_value(fallback_mtu)
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
	if(mtu < min_chunk_size)
		throw(hard_exception("GenericSocket::mtu mtu value too small"));

	if(mtu > max_chunk_size)
		throw(hard_exception("GenericSocket::mtu mtu value too large"));

	this->mtu_value = mtu;
}

void GenericSocket::send(const std::string &data, const int timeout) const
{
	unsigned int offset, chunk_size;
	int timeout_left;
	struct timeval start, now, span;

	if(debug)
		std::cerr << "GenericSocket::send called" << std::endl;

	if(timeout > 0)
		gettimeofday(&start, nullptr);

	for(offset = 0; offset < data.length(); offset += chunk_size)
	{
		chunk_size = data.length() - offset;

		if(chunk_size > mtu_value)
			chunk_size = mtu_value;

		if(timeout > 0)
		{
			gettimeofday(&now, nullptr);
			timersub(&now, &start, &span);

			timeout_left = timeout - (span.tv_sec * 1000) - (span.tv_usec / 1000);

			if(timeout_left <= 0)
				throw(transient_exception("GenericSocket::send: timeout"));
		}
		else
			timeout_left = timeout;

		if(debug)
			std::cerr << boost::format("send timeout: %d, timeout_left: %d\n") % timeout % timeout_left;

		this->_send(data.substr(offset, chunk_size), timeout_left);
	}
}

void GenericSocket::receive(std::string &data, const int timeout) const
{
	int timeout_left;
	struct timeval start, now, span;

	if(debug)
		std::cerr << "GenericSocket::receive called" << std::endl;

	if(timeout > 0)
		gettimeofday(&start, nullptr);

	data.clear();

	while(data.length() < max_chunk_size)
	{
		if(timeout > 0)
		{
			gettimeofday(&now, nullptr);
			timersub(&now, &start, &span);

			timeout_left = timeout - (span.tv_sec * 1000) - (span.tv_usec / 1000);

			if(timeout_left <= 0)
				throw(transient_exception("GenericSocket::receive: timeout"));
		}
		else
			timeout_left = timeout;

		if(debug)
			std::cerr << boost::format("receive timeout: %d, timeout_left: %d\n") % timeout % timeout_left;

		this->_receive(data, timeout_left);

		if(debug)
			std::cerr << boost::format("received data is now %u\n") % data.length();

		if(!Packet::valid(data))
		{
			if(debug)
				std::cerr << "receive finished due to no packet signature in first packet" << std::endl;

			break;
		}

		if(Packet::complete(data, verbose))
		{
			if(debug)
				std::cerr << "receive finished due to packet complete" << std::endl;

			break;
		}

		if(debug)
			std::cerr << "receive not finished" << std::endl;
	}

	if(data.length() >= (max_chunk_size + extra_chunk_size))
	{
		unsigned int length = data.length();
		data.clear();
		throw(hard_exception(boost::format("GenericSocket::receive: oversized packet received: %u") % length));
	}
}

void GenericSocket::drain(int timeout) const
{
	if(debug)
		std::cerr << "GenericSocket::drain called" << std::endl;

	if(timeout < 0)
		throw(hard_exception("drain: timeout value negative"));

	this->_drain(timeout);
}
