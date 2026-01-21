#include "packet.h"
#include "packet_header.h"
#include "util.h"
#include "encryption.h"

#include <string>
#include <iostream>
#include <boost/format.hpp>

bool Packet::valid(const std::string &packet)
{
	const packet_header_t *packet_header = (const packet_header_t *)packet.data();

	return((packet.length() >= sizeof(*packet_header)) &&
			(packet_header->soh == packet_header_soh) &&
			(packet_header->version == packet_header_version) &&
			(packet_header->id == packet_header_id));
}

bool Packet::complete(const std::string &packet)
{
	const packet_header_t *packet_header = (const packet_header_t *)packet.data();
	unsigned int packet_length = packet.length();
	unsigned int expected_length = (unsigned int)(packet_header->header_length + packet_header->payload_length + packet_header->oob_length);

	if(packet_length < expected_length)
		return(false);

	return(true);
}

std::string Packet::encapsulate(const std::string &data, const std::string &oob_data, bool packetised, bool verbose, bool debug)
{
	std::string packet;

	if(packetised)
	{
		uint32_t crc32;
		unsigned int checksummed, crc32_padding;
		packet_header_t packet_header;

		memset(&packet_header, 0, sizeof(packet_header));
		packet_header.soh = packet_header_soh;
		packet_header.version = packet_header_version;
		packet_header.id = packet_header_id;
		packet_header.header_length = sizeof(packet_header);
		packet_header.payload_length = data.length();
		packet_header.oob_length = oob_data.length();

		crc32 = Encryption::crc32();
		crc32 = Encryption::crc32(crc32, std::string_view(reinterpret_cast<const char *>(&packet_header), offsetof(packet_header_t, header_checksum)));
		packet_header.header_checksum = crc32;

		checksummed = 0;
		crc32 = Encryption::crc32();
		crc32 = Encryption::crc32(crc32, std::string_view(reinterpret_cast<const char *>(&packet_header), offsetof(packet_header_t, packet_checksum)));
		checksummed += offsetof(packet_header_t, packet_checksum);
		crc32 = Encryption::crc32(crc32, data);
		checksummed += data.length();
		crc32 = Encryption::crc32(crc32, oob_data);
		checksummed += oob_data.length();
		crc32_padding = (4 - (checksummed & 0x03)) & 0x03;
		std::string padding(crc32_padding, static_cast<char>(0x00));
		crc32 = Encryption::crc32(crc32, padding);

		packet_header.packet_checksum = crc32;

		packet.assign((const char *)&packet_header, sizeof(packet_header));
		packet.append(data);
		packet.append(oob_data);
	}
	else
	{
		packet = data;

		if((packet.length() == 0) || (packet.back() != '\n'))
			packet.append(1, '\n');

		if(oob_data.length() > 0)
		{
			packet.append(1, '\0');
			packet.append(oob_data);
		}
	}

	return(packet);
}

bool Packet::decapsulate(const std::string &packet, std::string &data, std::string &oob_data, bool packetised, bool verbose, bool debug)
{
	uint32_t our_checksum;
	unsigned checksummed, crc32_padding;

	if(packetised)
	{
		const packet_header_t *packet_header = (const packet_header_t *)packet.data();

		if(packet_header->header_length != sizeof(*packet_header))
			std::cerr << boost::format("decapsulate: invalid packet header length, expected: %u, received: %u") % sizeof(*packet_header) % (unsigned int)packet_header->header_length << std::endl;

		if((unsigned int)(packet_header->header_length + packet_header->payload_length + packet_header->oob_length) != packet.length())
			std::cerr << boost::format("decapsulate: invalid packet length, expected: %u, received: %u") %
				(packet_header->header_length + packet_header->payload_length + packet_header->oob_length) %
				packet.length() << std::endl;

		if(debug)
		{
			std::cerr << "Packet: data is packetised" << std::endl;
			std::cerr << boost::format("  soh: 0x%02x\n") % (unsigned int)packet_header->soh;
			std::cerr << boost::format("  version: 0x%02x\n") % (unsigned int)packet_header->version;
			std::cerr << boost::format("  id: 0x%04x\n") % (unsigned int)packet_header->id;
			std::cerr << boost::format("  header length: 0x%04x\n") % (unsigned int)packet_header->header_length;
			std::cerr << boost::format("  payload length: 0x%04x\n") % (unsigned int)packet_header->payload_length;
			std::cerr << boost::format("  oob length: 0x%04x\n") % (unsigned int)packet_header->oob_length;
			std::cerr << boost::format("  header checksum: 0x%04x\n") % (unsigned int)packet_header->header_checksum;
			std::cerr << boost::format("  packet checksum: 0x%04x\n") % (unsigned int)packet_header->packet_checksum;
		}

		our_checksum = Encryption::crc32();
		our_checksum = Encryption::crc32(our_checksum, std::string_view(reinterpret_cast<const char *>(packet_header), offsetof(packet_header_t, header_checksum)));

		if(our_checksum != packet_header->header_checksum)
		{
			if(verbose)
				std::cerr << boost::format("decapsulate: invalid header checksum, ours: 0x%x, theirs: 0x%x") % our_checksum % (unsigned int)packet_header->header_checksum << std::endl;

			return(false);
		}

		data = packet.substr(packet_header->header_length, packet_header->payload_length);
		oob_data = packet.substr(packet_header->header_length + packet_header->payload_length);

		checksummed = 0;
		our_checksum = Encryption::crc32();
		our_checksum = Encryption::crc32(our_checksum, std::string_view(reinterpret_cast<const char *>(packet_header), offsetof(packet_header_t, packet_checksum)));
		checksummed += offsetof(packet_header_t, packet_checksum);
		our_checksum = Encryption::crc32(our_checksum, data);
		checksummed += data.length();
		our_checksum = Encryption::crc32(our_checksum, oob_data);
		checksummed += oob_data.length();
		crc32_padding = (4 - (checksummed & 0x03)) & 0x03;
		std::string padding(crc32_padding, static_cast<char>(0x00));
		our_checksum = Encryption::crc32(our_checksum, padding);

		if(our_checksum != packet_header->packet_checksum)
		{
			if(verbose)
				std::cerr << boost::format("decapsulate: invalid packet checksum, ours: 0x%x, theirs: 0x%x") % our_checksum % (unsigned int)packet_header->packet_checksum << std::endl;

			return(false);
		}
	}
	else
	{
		size_t oob_offset;

		if(debug)
			std::cerr << "Packet: data is not packetised" << std::endl;

		oob_offset = packet.find('\0', 0);

		if(oob_offset == std::string::npos)
		{
			data = packet;
			oob_data.clear();
		}
		else
		{
			if((oob_offset + 1) > packet.length())
			{
				if(verbose)
				{
					std::cerr << "invalid unpacketised oob data" << std::endl;
					std::cerr << "oob_offset: " << oob_offset << ", data length: " << data.length() << std::endl;
				}

				data.clear();
				oob_data.clear();

				return(false);
			}

			data = packet.substr(0, oob_offset);
			oob_data = packet.substr(oob_offset + 1);
		}
	}

	if((data.back() == '\n') || (data.back() == '\r'))
		data.pop_back();

	if((data.back() == '\n') || (data.back() == '\r'))
		data.pop_back();

	return(true);
}
