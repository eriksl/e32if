#include "packet.h"
#include <openssl/evp.h>
#include <string>
#include <iostream>
#include <boost/format.hpp>

enum
{
	md5_hash_size = 16,
};

uint32_t Packet::MD5_trunc_32(const std::string &data) noexcept
{
	uint8_t hash[md5_hash_size];
	uint32_t checksum;
	unsigned int hash_size;
	EVP_MD_CTX *hash_ctx;

	hash_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(hash_ctx, EVP_md5(), (ENGINE *)0);
	EVP_DigestUpdate(hash_ctx, data.data(), data.length());
	hash_size = md5_hash_size;
	EVP_DigestFinal_ex(hash_ctx, hash, &hash_size);
	EVP_MD_CTX_free(hash_ctx);

	checksum = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | (hash[3] << 0);

	return(checksum);
}

void Packet::clear_packet_header() noexcept
{
	packet_header.soh = 0;
	packet_header.version = 0;
	packet_header.id = 0;
	packet_header.length = 0;
	packet_header.data_offset = 0;
	packet_header.data_pad_offset = 0;
	packet_header.oob_data_offset = 0;
	packet_header.broadcast_groups = 0;
	packet_header.flags = 0;
	packet_header.spare_0 = 0;
	packet_header.spare_1 = 0;
	packet_header.checksum = 0;
}

Packet::Packet()
{
	clear();
}

Packet::Packet(const std::string &data_in, const std::string &oob_data_in)
{
	clear();

	data = data_in;
	oob_data = oob_data_in;
}

void Packet::clear()
{
	data.clear();
	oob_data.clear();
	clear_packet_header();
}

void Packet::append_data(const std::string &data_in)
{
	data.append(data_in);
}

void Packet::append_oob_data(const std::string &oob_data_in)
{
	oob_data.append(oob_data_in);
}

std::string Packet::encapsulate(bool raw)
{
	std::string pad;
	std::string packet;

	if(raw)
	{
		packet = data;

		if((packet.length() > 0) && (packet.back() != '\n'))
			packet.append(1, '\n');

		if(oob_data.length() > 0)
		{
			packet.append(1, '\0');

			while((packet.length() % 4) != 0)
				packet.append(1, '\0');

			packet.append(oob_data);
		}
	}
	else
	{
		clear_packet_header();

		if(oob_data.length() > 0)
			while(((data.length() + pad.length()) % 4) != 0)
				pad.append(1, '\0');

		packet_header.soh = packet_header_soh;
		packet_header.version = packet_header_version;
		packet_header.id = packet_header_id;
		packet_header.length = sizeof(packet_header) + data.length() + pad.length() + oob_data.length();
		packet_header.data_offset = sizeof(packet_header);
		packet_header.data_pad_offset = sizeof(packet_header) + data.length();
		packet_header.oob_data_offset = sizeof(packet_header) + data.length() + pad.length();
		packet_header.flag.md5_32_requested = 1;
		packet_header.broadcast_groups = 0;

		packet_header.flag.md5_32_provided = 1;
		std::string packet_checksum = std::string((const char *)&packet_header, sizeof(packet_header)) + data + pad + oob_data;
		packet_header.checksum = MD5_trunc_32(packet_checksum);

		packet = std::string((const char *)&packet_header, sizeof(packet_header)) + data + pad + oob_data;
	}

	return(packet);
}

bool Packet::decapsulate(std::string *data_in, std::string *oob_data_in, bool verbose, bool *rawptr)
{
	bool raw = false;
	unsigned int our_checksum;

	if(data.length() < sizeof(packet_header))
		raw = true;
	else
	{
		packet_header = *(packet_header_t *)data.data();

		if((packet_header.soh != packet_header_soh) || (packet_header.id != packet_header_id))
			raw = true;
	}

	if(raw)
	{
		size_t padding_offset, oob_data_offset;

		clear_packet_header();

		padding_offset = data.find('\0', 0);

		if(padding_offset == std::string::npos)
			oob_data.clear();
		else
		{
			oob_data_offset = padding_offset + 1;

			while((oob_data_offset % 4) != 0)
				oob_data_offset++;

			if(oob_data_offset < data.length())
				oob_data = data.substr(oob_data_offset);
			else
			{
				if(verbose)
					std::cerr << "invalid raw oob data padding" << std::endl;

				oob_data.clear();
			}

			data.erase(padding_offset);
		}
	}
	else
	{
		packet_header = *(packet_header_t *)data.data();

		if(packet_header.version != packet_header_version)
		{
			if(verbose)
				std::cerr << boost::format("decapsulate: wrong version packet received: %u") % packet_header.version << std::endl;

			return(false);
		}

		if(packet_header.flag.md5_32_provided)
		{
			packet_header_t packet_header_checksum = packet_header;
			std::string data_checksum;

			packet_header_checksum.checksum = 0;
			data_checksum = std::string((const char *)&packet_header_checksum, sizeof(packet_header_checksum)) + data.substr(packet_header.data_offset);
			our_checksum = MD5_trunc_32(data_checksum);

			if(our_checksum != packet_header.checksum)
			{
				if(verbose)
					std::cerr << boost::format("decapsulate: invalid checksum, ours: 0x%x, theirs: 0x%x") % our_checksum % (unsigned int)packet_header.checksum << std::endl;

				return(false);
			}
		}

		if((packet_header.oob_data_offset != packet_header.length) && ((packet_header.oob_data_offset % 4) != 0))
		{
			if(verbose)
				std::cerr << boost::format("packet oob data padding invalid: %u") % (unsigned int)packet_header.oob_data_offset << std::endl;
			oob_data.clear();
		}
		else
		{
			oob_data = data.substr(packet_header.oob_data_offset);
			data = data.substr(packet_header.data_offset, packet_header.data_pad_offset - packet_header.data_offset);
		}
	}

	if((data.back() == '\n') || (data.back() == '\r'))
		data.pop_back();

	if((data.back() == '\n') || (data.back() == '\r'))
		data.pop_back();

	if(data_in)
		*data_in = data;

	if(oob_data_in)
		*oob_data_in = oob_data;

	if(rawptr)
		*rawptr = raw;

	return(true);
}

void Packet::query(bool &valid, bool &complete) noexcept
{
	packet_header = *(packet_header_t *)data.data();

	if(data.length() >= sizeof(packet_header) &&
			(packet_header.soh == packet_header_soh) &&
			(packet_header.id == packet_header_id))
	{
		valid = true;
		complete = data.length() >= packet_header.length;
	}
	else
	{
		valid = false;
		complete = false;
	}
}
