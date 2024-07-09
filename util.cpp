#include "util.h"
#include "packet.h"
#include "exception.h"

#include <string>
#include <iostream>
#include <typeinfo>
#include <boost/format.hpp>
#include <boost/regex.hpp>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

std::string Util::encrypt_aes_256(std::string input_string)
{
	static const uint8_t aes_256_key[32] =
	{
		0x3a, 0xe0, 0xbe, 0x96, 0xeb, 0x7c, 0xfe, 0xbc, 0x97, 0xe9, 0x7e, 0x98, 0x73, 0x8e, 0x4e, 0x88,
		0xeb, 0xd7, 0x76, 0xa7, 0x55, 0x8a, 0xd3, 0x36, 0x96, 0x4b, 0xaf, 0x0b, 0x35, 0xa4, 0x84, 0xf5,
	};

	static const uint8_t aes_256_iv[16] = { 0x4f, 0x8f, 0xee, 0x60, 0xe9, 0x56, 0x4d, 0x0f, 0x81, 0xf0, 0x8a, 0xe5, 0x8d, 0x1c, 0x08, 0xd6 };

	EVP_CIPHER_CTX *context = (EVP_CIPHER_CTX *)0;
	EVP_CIPHER *cipher = (EVP_CIPHER *)0;
	uint8_t output[16];
	std::string output_string;
	int chunk_in, chunk_out;

	try
	{
		if(!(context = EVP_CIPHER_CTX_new()))
			throw(hard_exception("encrypt_aes_256: new failed"));

		if(!(cipher = EVP_CIPHER_fetch((OSSL_LIB_CTX *)0, "AES-256-CBC", (const char *)0)))
			throw(hard_exception("encrypt_aes_256: EVP_CIPHER_fetch failed"));

		if(!EVP_EncryptInit_ex2(context, cipher, aes_256_key, aes_256_iv, (const OSSL_PARAM *)0))
			throw(hard_exception("encrypt_aes_256: EncryptInit_ex2 failed"));

		while((chunk_in = input_string.length()) > 0)
		{
			if(chunk_in > 16)
				chunk_in = 16;

			if(!EVP_EncryptUpdate(context, output, &chunk_out, (const unsigned char *)input_string.data(), chunk_in))
				throw(hard_exception("encrypt_aes_256: EVP_encryptUpdate failed"));

			if(chunk_out > 16)
				throw(hard_exception("encrypt_aes_256: output buffer overflow"));

			input_string.erase(0, chunk_in);
			output_string.append((const char *)output, (size_t)chunk_out);
		}

		if(!EVP_EncryptFinal_ex(context, output, &chunk_out))
			throw(hard_exception("encrypt_aes_256: EVP_EncryptFinal_ex failed"));

		output_string.append((const char *)output, (size_t)chunk_out);
	}
	catch(...)
	{
		if(cipher)
			EVP_CIPHER_free(cipher);

		if(context)
			EVP_CIPHER_CTX_free(context);

		throw;
	}

	EVP_CIPHER_free(cipher);
	EVP_CIPHER_CTX_free(context);

	return(output_string);
}

Util::Util(GenericSocket *channel_in, const e32_config &config_in) noexcept
	:
		config(config_in)
{
	channel = channel_in;
}

std::string Util::dumper(const char *id, const std::string text)
{
	int ix;
	char current;
	std::string out;

	out = (boost::format("%s[%d]: \"") % id % text.length()).str();

	for(ix = 0; (ix < (int)text.length()) && (ix < 512); ix++)
	{
		current = text.at(ix);

		if((current >= ' ') && (current <= '~'))
			out.append(1, current);
		else
			out.append((boost::format("[%02x]") % ((unsigned int)current & 0xff)).str());
	}

	out.append("\"");

	return(out);
}

std::string Util::hash_to_text(unsigned int length, const unsigned char *hash)
{
	unsigned int current;
	std::string hash_string;

	for(current = 0; current < length; current++)
		hash_string.append((boost::format("%02x") % (unsigned int)hash[current]).str());

	return(hash_string);
}

int Util::process(const std::string &data, const std::string &oob_data, std::string &reply_data, std::string *reply_oob_data,
		const char *match, std::vector<std::string> *string_value, std::vector<int> *int_value, int timeout) const
{
	enum { max_attempts = 8 };
	unsigned int attempt;
	std::string send_data;
	std::string packet;
	Packet receive_packet;
	std::string receive_data;
	boost::smatch capture;
	boost::regex re(match ? match : "");
	unsigned int captures;
	bool packet_valid;
	bool packet_complete, raw_complete;

	if(config.debug)
		std::cout << Util::dumper("data", data) << std::endl;

	packet = Packet(data, oob_data).encapsulate(config.raw, config.provide_checksum, config.request_checksum, config.broadcast_group_mask);

	if(timeout < 0)
		timeout = 2000;

	for(attempt = 0; attempt < max_attempts; attempt++)
	{
		try
		{
			send_data = packet;

			while(!channel->send(send_data, timeout));

			for(receive_data.clear();;)
			{
				raw_complete = channel->receive(receive_data, timeout);
				receive_packet.clear();
				receive_packet.append_data(receive_data);
				receive_packet.query(packet_valid, packet_complete);

				if(packet_valid)
				{
					if(packet_complete)
						break;
				}
				else
					if(raw_complete)
						break;
			}

			if(!receive_packet.decapsulate(&reply_data, reply_oob_data, config.verbose))
				throw(transient_exception("decapsulation failed"));

			if(match && !boost::regex_match(reply_data, capture, re))
				throw(transient_exception(boost::format("received string does not match: \"%s\" vs. \"%s\"") % Util::dumper("reply", reply_data) % match));

			break;
		}
		catch(const transient_exception &e)
		{
			if(config.verbose)
				std::cout << boost::format("process attempt #%u failed: %s, backoff %u ms") % attempt % e.what() % timeout << std::endl;

			usleep(timeout * 1000);
			channel->drain();
			timeout *= 2;

			continue;
		}
	}

	if(config.verbose && (attempt > 0))
		std::cerr << boost::format("success at attempt %u") % attempt << std::endl;

	if(attempt >= max_attempts)
		throw(hard_exception("process: no more attempts"));

	if(string_value || int_value)
	{
		if(string_value)
			string_value->clear();

		if(int_value)
			int_value->clear();

		captures = 0;

		for(const auto &it : capture)
		{
			if(captures++ == 0)
				continue;

			if(string_value)
				string_value->push_back(it);

			if(int_value)
			{
				try
				{
					int_value->push_back(stoi(it, 0, 0));
				}
				catch(std::invalid_argument &)
				{
					int_value->push_back(0);
				}
				catch(std::out_of_range &)
				{
					int_value->push_back(0);
				}
			}
		}
	}

	if(config.debug)
	{
		std::cout << Util::dumper("reply", reply_data) << std::endl;

		if(reply_oob_data)
			std::cout << reply_oob_data->length () << " bytes OOB data received" << std::endl;
		else
			std::cout << "no oob data requested" << std::endl;
	}

	return(attempt);
}

int Util::read_sector(unsigned int sector_size, unsigned int sector, std::string &data, int timeout) const
{
	std::string reply;
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	int retries;

	try
	{
		retries = process((boost::format("flash-read %u\n") % sector).str(), "",
				reply, &data, "OK flash-read: read sector ([0-9]+)", &string_value, &int_value, timeout);
	}
	catch(const hard_exception &e)
	{
		throw(hard_exception(boost::format("read sector: hard exception: %s") % e.what()));
	}
	catch(const transient_exception &e)
	{
		throw(transient_exception(boost::format("read sector: transient exception: %s") % e.what()));
	}

	if(data.length() < sector_size)
	{
		if(config.verbose)
			std::cout << boost::format("flash sector read failed: incorrect length, expected: %u, received: %u, reply: %s") %
					sector_size % data.length() % reply << std::endl;

		throw(transient_exception(boost::format("read_sector failed: incorrect length (%u vs. %u)") % sector_size % data.length()));
	}

	if(int_value[0] != (int)sector)
	{
		if(config.verbose)
			std::cout << boost::format("flash sector read failed: local sector #%u != remote sector #%u") % sector % int_value[0] << std::endl;

		throw(transient_exception(boost::format("read sector failed: incorrect sector (%u vs. %u)") % sector % int_value[0]));
	}

	return(retries);
}

int Util::write_sector(unsigned int sector, const std::string &data,
		unsigned int &written, unsigned int &erased, unsigned int &skipped, bool simulate) const
{
	std::string command;
	std::string reply;
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	unsigned int attempt;
	unsigned int process_tries;

	command = (boost::format("flash-write %u %u") % (simulate ? 0 : 1) % sector).str();

	for(attempt = 4; attempt > 0; attempt--)
	{
		try
		{
			process_tries = process(command, data,
					reply, nullptr, "OK flash-write: written mode ([01]), sector ([0-9]+), same ([01]), erased ([01])", &string_value, &int_value);

			if(int_value[0] != (simulate ? 0 : 1))
				throw(transient_exception(boost::format("invalid mode (%u vs. %u)") % (simulate ? 0 : 1) % int_value[0]));

			if(int_value[1] != (int)sector)
				throw(transient_exception(boost::format("wrong sector (%u vs %u)") % sector % int_value[0]));

			if(int_value[2] != 0)
				skipped++;
			else
				written++;

			if(int_value[3] != 0)
				erased++;

			break;
		}
		catch(const transient_exception &e)
		{
			std::cerr << std::endl << boost::format("flash sector write failed temporarily: %s, reply: %s ") % e.what() % reply << std::endl;
			continue;
		}
	}

	if(attempt == 0)
		throw(hard_exception("write sector: no more attempts"));

	return(process_tries);
}

void Util::get_checksum(unsigned int sector, unsigned int sectors, std::string &checksum, int timeout) const
{
	std::string reply;
	std::vector<int> int_value;
	std::vector<std::string> string_value;

	try
	{
		process((boost::format("flash-checksum %u %u\n") % sector % sectors).str(), "",
				reply, nullptr, "OK flash-checksum: checksummed ([0-9]+) sectors from sector ([0-9]+), checksum: ([0-9a-f]+)",
				&string_value, &int_value, timeout);
	}
	catch(const transient_exception &e)
	{
		boost::format fmt("flash sector checksum failed temporarily: %s, reply: %s");

		fmt % e.what() % reply;

		if(config.verbose)
			std::cout << fmt << std::endl;

		throw(transient_exception(fmt));
	}
	catch(const hard_exception &e)
	{
		boost::format fmt("flash sector checksum failed: %s, reply: %s");

		fmt % e.what() % reply;

		if(config.verbose)
			std::cout << fmt << std::endl;

		throw(hard_exception(fmt));
	}

	if(int_value[0] != (int)sectors)
	{
		boost::format fmt("flash sector checksum failed: local sectors (%u) != remote sectors (%u)");

		fmt % sectors % int_value[0];

		if(config.verbose)
			std::cout << fmt << std::endl;

		throw(transient_exception(fmt));
	}

	if(int_value[1] != (int)sector)
	{
		boost::format fmt("flash sector checksum failed: local start sector (%u) != remote start sector (%u)");

		fmt % sector % int_value[1];

		if(config.verbose)
			std::cout << fmt << std::endl;

		throw(transient_exception(fmt));
	}

	checksum = string_value[2];
}
