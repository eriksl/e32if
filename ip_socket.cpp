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

IPSocket::IPSocket(const e32_config &config_in) :
	GenericSocket(config_in)
{
	memset(&saddr, 0, sizeof(saddr));
}

IPSocket::~IPSocket() noexcept
{
}

void IPSocket::connect(int timeout)
{
	struct addrinfo hints;
	struct addrinfo *res = nullptr;
	int socket_argument;

	if(config.transport == transport_tcp_ip)
		socket_argument = SOCK_STREAM | SOCK_NONBLOCK;
	else
		socket_argument = SOCK_DGRAM;

	if((socket_fd = socket(AF_INET, socket_argument, 0)) < 0)
		throw(hard_exception("socket failed"));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = config.transport == transport_tcp_ip ? SOCK_STREAM : SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICSERV;

	if(getaddrinfo(config.host.c_str(), config.command_port.c_str(), &hints, &res))
	{
		if(res)
			freeaddrinfo(res);
		throw(hard_exception("unknown host"));
	}

	if(!res || !res->ai_addr)
		throw(hard_exception("unknown host"));

	saddr = *(struct sockaddr_in *)res->ai_addr;
	freeaddrinfo(res);

	if(config.broadcast)
	{
		int arg = 1;

		if(setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &arg, sizeof(arg)))
		{
			if(config.verbose)
				perror("setsockopt SO_BROADCAST\n");
			throw(hard_exception("set broadcast"));
		}
	}

	if(config.multicast)
	{
		struct ip_mreq mreq;
		int arg = 3;

		if(setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_TTL, &arg, sizeof(arg)))
			throw(hard_exception("multicast: cannot set mc ttl"));

		arg = 0;

		if(setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &arg, sizeof(arg)))
			throw(hard_exception("multicast: cannot set loopback"));

		mreq.imr_multiaddr = saddr.sin_addr;
		mreq.imr_interface.s_addr = INADDR_ANY;

		if(setsockopt(socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)))
			throw(hard_exception("multicast: cannot join mc group"));
	}

	if(config.transport == transport_tcp_ip)
	{
		struct pollfd pfd;

		pfd.fd = socket_fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;

		try
		{
			if((::connect(socket_fd, (const struct sockaddr *)&saddr, sizeof(saddr))) && (errno != EINPROGRESS))
				throw("tcp connect: connect failed");

			if(poll(&pfd, 1, timeout < 0 ? 500 : timeout) != 1)
				throw("tcp connect: timeout");

			if(pfd.revents & (POLLERR | POLLHUP))
				throw("tcp connect: connect event error");

			if(!(pfd.revents & POLLOUT))
				throw("tcp connect: connect event unfinished");
		}
		catch(const char *e)
		{
			throw(hard_exception(config.host + ": " + e));
		}
	}
}

void IPSocket::disconnect() noexcept
{
	GenericSocket::disconnect();
}

bool IPSocket::send(std::string &data, int timeout) const
{
	struct pollfd pfd;
	int length;

	if(timeout < 0)
		timeout = config.broadcast ? 100 : 500;

	try
	{
		pfd.fd = socket_fd;
		pfd.events = POLLOUT | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(data.length() == 0)
			throw("empty_buffer");

		if(poll(&pfd, 1, timeout) != 1)
			throw("poll timeout");

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("poll error");

		if(config.transport == transport_tcp_ip)
		{
			if((length = ::send(socket_fd, data.data(), data.length(), 0)) <= 0)
				throw("send error");
		}
		else
		{
			if((length = ::sendto(socket_fd, data.data(), data.length(), 0, (const struct sockaddr *)&this->saddr, sizeof(this->saddr))) <= 0)
				throw("sendto error");
		}
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("ipsocket::send: %s (%s)") % e % strerror(errno)));
	}

	data.erase(0, length);

	return(data.length() == 0);
}

bool IPSocket::receive(std::string &data, int timeout, uint32_t *hostid, std::string *hostname) const
{
	int length;
	char buffer[2 * config.sector_size];
	struct sockaddr_in remote_host;
	socklen_t remote_host_length = sizeof(remote_host);
	char hostbuffer[64];
	char service[64];
	struct pollfd pfd = { .fd = socket_fd, .events = POLLIN | POLLERR | POLLHUP, .revents = 0 };

	if(timeout < 0)
		timeout = config.broadcast ? 100 : 500;

	try
	{
		if(poll(&pfd, 1, timeout) != 1)
			return(true);

		if(pfd.revents & (POLLERR | POLLHUP))
			throw("receive poll error");

		if(config.transport == transport_tcp_ip)
		{
			if((length = ::recv(socket_fd, buffer, sizeof(buffer) - 1, 0)) <= 0)
				throw("recv error");
		}
		else
		{
			if((length = ::recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0, (sockaddr *)&remote_host, &remote_host_length)) <= 0)
				throw("recvfrom error");
		}

		data.append(buffer, (size_t)length);

		if(hostid)
		{
			int error;
			*hostid = ntohl(remote_host.sin_addr.s_addr);

			if(hostname)
			{
				if((error = getnameinfo((struct sockaddr *)&remote_host, remote_host_length, hostbuffer, sizeof(hostbuffer),
						service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NOFQDN)) != 0)
				{
					if(config.verbose)
						std::cout << boost::format("cannot resolve: %s") % gai_strerror(error) << std::endl;

					*hostname = "0.0.0.0";
				}
				else
					*hostname = hostbuffer;
			}
		}
	}
	catch(const char *e)
	{
		throw(hard_exception(boost::format("ipsocket::receive: %s (%s)") % e % strerror(errno)));
	}

	if(config.transport == transport_tcp_ip)
		return((length < 1440) || (data.length() > 4096));
	else
		if(config.broadcast)
			return(false);
		else
			if(length == 1024 /* ESP32 workaround */)
				return(false);
			else
				return((length < 4096) || /* ESP8266 workaround */ (length == 4132));
}

void IPSocket::drain() const
{
	struct pollfd pfd;
	enum { drain_packets_buffer_size = 4, drain_packets = 16 };
	char *buffer = (char *)alloca(config.sector_size * drain_packets_buffer_size);
	int length;
	int bytes = 0;
	int packet = 0;

	if(config.verbose)
		std::cout << "draining..." << std::endl;

	for(packet = 0; packet < drain_packets; packet++)
	{
		pfd.fd = socket_fd;
		pfd.events = POLLIN | POLLERR | POLLHUP;
		pfd.revents = 0;

		if(poll(&pfd, 1, 500) != 1)
			break;

		if(pfd.revents & (POLLERR | POLLHUP))
			break;

		if(config.transport == transport_tcp_ip)
		{
			if((length = ::recv(socket_fd, buffer, config.sector_size * drain_packets_buffer_size, 0)) < 0)
				break;
		}
		else
		{
			if((length = ::recvfrom(socket_fd, buffer, config.sector_size * drain_packets_buffer_size, 0, (struct sockaddr *)0, 0)) < 0)
				break;
		}

		if(config.verbose)
			std::cout << Util::dumper("drain", std::string(buffer, length)) << std::endl;

		bytes += length;
	}

	if(config.verbose && (packet > 0))
		std::cout << boost::format("drained %u bytes in %u packets") % bytes % packet << std::endl;
}
