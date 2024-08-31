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

int Util::process(const std::string &data, const std::string &oob_data, std::string &reply_data, std::string *reply_oob_data_in,
		const char *match, std::vector<std::string> *string_value, std::vector<int> *int_value, int timeout) const
{
	enum { max_attempts = 8 };
	unsigned int attempt;
	std::string packet;
	std::string receive_data;
	std::string reply_oob_data;
	boost::smatch capture;
	boost::regex re(match ? match : "");
	unsigned int captures;
	bool packetised;

	if(config.debug)
		std::cerr << Util::dumper("data", data) << std::endl;

	packet = Packet::encapsulate(data, oob_data, !config.raw);

	if(timeout < 0)
		timeout = 10000;

	for(attempt = 0; attempt < max_attempts; attempt++)
	{
		try
		{
			channel->send(packet, timeout);
			channel->receive(receive_data, timeout);

			if(!Packet::decapsulate(receive_data, reply_data, reply_oob_data, packetised, config.verbose))
				throw(transient_exception("decapsulation failed"));

			if(reply_oob_data_in)
				*reply_oob_data_in = reply_oob_data;

			if(match && !boost::regex_match(reply_data, capture, re))
				throw(transient_exception(boost::format("received string does not match: \"%s\" vs. \"%s\"") % Util::dumper("reply", reply_data) % match));

			break;
		}
		catch(const transient_exception &e)
		{
			if(config.verbose)
				std::cerr << boost::format("process attempt #%u failed: %s, backoff %u ms") % attempt % e.what() % timeout << std::endl;

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
		std::cerr << Util::dumper("reply", reply_data) << std::endl;

		if(reply_oob_data.length())
			std::cerr << reply_oob_data.length () << " bytes OOB data received" << std::endl;
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
			std::cerr << boost::format("flash sector read failed: incorrect length, expected: %u, received: %u, reply: %s") %
					sector_size % data.length() % reply << std::endl;

		throw(transient_exception(boost::format("read_sector failed: incorrect length (%u vs. %u)") % sector_size % data.length()));
	}

	if(int_value[0] != (int)sector)
	{
		if(config.verbose)
			std::cerr << boost::format("flash sector read failed: local sector #%u != remote sector #%u") % sector % int_value[0] << std::endl;

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
			std::cerr << fmt << std::endl;

		throw(transient_exception(fmt));
	}
	catch(const hard_exception &e)
	{
		boost::format fmt("flash sector checksum failed: %s, reply: %s");

		fmt % e.what() % reply;

		if(config.verbose)
			std::cerr << fmt << std::endl;

		throw(hard_exception(fmt));
	}

	if(int_value[0] != (int)sectors)
	{
		boost::format fmt("flash sector checksum failed: local sectors (%u) != remote sectors (%u)");

		fmt % sectors % int_value[0];

		if(config.verbose)
			std::cerr << fmt << std::endl;

		throw(transient_exception(fmt));
	}

	if(int_value[1] != (int)sector)
	{
		boost::format fmt("flash sector checksum failed: local start sector (%u) != remote start sector (%u)");

		fmt % sector % int_value[1];

		if(config.verbose)
			std::cerr << fmt << std::endl;

		throw(transient_exception(fmt));
	}

	checksum = string_value[2];
}

// code below slightly modified from https://github.com/madler/crcany, zlib license

uint32_t const Util::crc32_table_byte[] =
{
	0xb1f7404b, 0xb5365dfc, 0xb8757b25, 0xbcb46692, 0xa2f33697, 0xa6322b20,
	0xab710df9, 0xafb0104e, 0x97ffadf3, 0x933eb044, 0x9e7d969d, 0x9abc8b2a,
	0x84fbdb2f, 0x803ac698, 0x8d79e041, 0x89b8fdf6, 0xfde69b3b, 0xf927868c,
	0xf464a055, 0xf0a5bde2, 0xeee2ede7, 0xea23f050, 0xe760d689, 0xe3a1cb3e,
	0xdbee7683, 0xdf2f6b34, 0xd26c4ded, 0xd6ad505a, 0xc8ea005f, 0xcc2b1de8,
	0xc1683b31, 0xc5a92686, 0x29d4f6ab, 0x2d15eb1c, 0x2056cdc5, 0x2497d072,
	0x3ad08077, 0x3e119dc0, 0x3352bb19, 0x3793a6ae, 0x0fdc1b13, 0x0b1d06a4,
	0x065e207d, 0x029f3dca, 0x1cd86dcf, 0x18197078, 0x155a56a1, 0x119b4b16,
	0x65c52ddb, 0x6104306c, 0x6c4716b5, 0x68860b02, 0x76c15b07, 0x720046b0,
	0x7f436069, 0x7b827dde, 0x43cdc063, 0x470cddd4, 0x4a4ffb0d, 0x4e8ee6ba,
	0x50c9b6bf, 0x5408ab08, 0x594b8dd1, 0x5d8a9066, 0x8571303c, 0x81b02d8b,
	0x8cf30b52, 0x883216e5, 0x967546e0, 0x92b45b57, 0x9ff77d8e, 0x9b366039,
	0xa379dd84, 0xa7b8c033, 0xaafbe6ea, 0xae3afb5d, 0xb07dab58, 0xb4bcb6ef,
	0xb9ff9036, 0xbd3e8d81, 0xc960eb4c, 0xcda1f6fb, 0xc0e2d022, 0xc423cd95,
	0xda649d90, 0xdea58027, 0xd3e6a6fe, 0xd727bb49, 0xef6806f4, 0xeba91b43,
	0xe6ea3d9a, 0xe22b202d, 0xfc6c7028, 0xf8ad6d9f, 0xf5ee4b46, 0xf12f56f1,
	0x1d5286dc, 0x19939b6b, 0x14d0bdb2, 0x1011a005, 0x0e56f000, 0x0a97edb7,
	0x07d4cb6e, 0x0315d6d9, 0x3b5a6b64, 0x3f9b76d3, 0x32d8500a, 0x36194dbd,
	0x285e1db8, 0x2c9f000f, 0x21dc26d6, 0x251d3b61, 0x51435dac, 0x5582401b,
	0x58c166c2, 0x5c007b75, 0x42472b70, 0x468636c7, 0x4bc5101e, 0x4f040da9,
	0x774bb014, 0x738aada3, 0x7ec98b7a, 0x7a0896cd, 0x644fc6c8, 0x608edb7f,
	0x6dcdfda6, 0x690ce011, 0xd8fba0a5, 0xdc3abd12, 0xd1799bcb, 0xd5b8867c,
	0xcbffd679, 0xcf3ecbce, 0xc27ded17, 0xc6bcf0a0, 0xfef34d1d, 0xfa3250aa,
	0xf7717673, 0xf3b06bc4, 0xedf73bc1, 0xe9362676, 0xe47500af, 0xe0b41d18,
	0x94ea7bd5, 0x902b6662, 0x9d6840bb, 0x99a95d0c, 0x87ee0d09, 0x832f10be,
	0x8e6c3667, 0x8aad2bd0, 0xb2e2966d, 0xb6238bda, 0xbb60ad03, 0xbfa1b0b4,
	0xa1e6e0b1, 0xa527fd06, 0xa864dbdf, 0xaca5c668, 0x40d81645, 0x44190bf2,
	0x495a2d2b, 0x4d9b309c, 0x53dc6099, 0x571d7d2e, 0x5a5e5bf7, 0x5e9f4640,
	0x66d0fbfd, 0x6211e64a, 0x6f52c093, 0x6b93dd24, 0x75d48d21, 0x71159096,
	0x7c56b64f, 0x7897abf8, 0x0cc9cd35, 0x0808d082, 0x054bf65b, 0x018aebec,
	0x1fcdbbe9, 0x1b0ca65e, 0x164f8087, 0x128e9d30, 0x2ac1208d, 0x2e003d3a,
	0x23431be3, 0x27820654, 0x39c55651, 0x3d044be6, 0x30476d3f, 0x34867088,
	0xec7dd0d2, 0xe8bccd65, 0xe5ffebbc, 0xe13ef60b, 0xff79a60e, 0xfbb8bbb9,
	0xf6fb9d60, 0xf23a80d7, 0xca753d6a, 0xceb420dd, 0xc3f70604, 0xc7361bb3,
	0xd9714bb6, 0xddb05601, 0xd0f370d8, 0xd4326d6f, 0xa06c0ba2, 0xa4ad1615,
	0xa9ee30cc, 0xad2f2d7b, 0xb3687d7e, 0xb7a960c9, 0xbaea4610, 0xbe2b5ba7,
	0x8664e61a, 0x82a5fbad, 0x8fe6dd74, 0x8b27c0c3, 0x956090c6, 0x91a18d71,
	0x9ce2aba8, 0x9823b61f, 0x745e6632, 0x709f7b85, 0x7ddc5d5c, 0x791d40eb,
	0x675a10ee, 0x639b0d59, 0x6ed82b80, 0x6a193637, 0x52568b8a, 0x5697963d,
	0x5bd4b0e4, 0x5f15ad53, 0x4152fd56, 0x4593e0e1, 0x48d0c638, 0x4c11db8f,
	0x384fbd42, 0x3c8ea0f5, 0x31cd862c, 0x350c9b9b, 0x2b4bcb9e, 0x2f8ad629,
	0x22c9f0f0, 0x2608ed47, 0x1e4750fa, 0x1a864d4d, 0x17c56b94, 0x13047623,
	0x0d432626, 0x09823b91, 0x04c11d48, 0x000000ff
};

uint32_t Util::crc32cksum_byte(uint32_t crc, void const *mem, size_t len)
{
	const uint8_t *data = static_cast<const uint8_t *>(mem);

	if(!data)
		return(0xffffffffUL);

	for(size_t i = 0; i < len; i++)
		crc = (crc << 8) ^ crc32_table_byte[((crc >> 24) ^ data[i]) & 0xff];

	return(crc);
}
