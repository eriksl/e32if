#include "command.h"
#include "packet.h"
#include "exception.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netdb.h>
#include <string.h>
#include <openssl/evp.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <boost/format.hpp>
#include <Magick++.h>

// FIXME
static const char *flash_info_expect = "ok flash function available, slots: 2, current: ([0-9]+), sectors: \\[ ([0-9]+), ([0-9]+) \\], display: ([0-9]+)x([0-9]+)px@([0-9]+)";

enum
{
	sha1_hash_size = 20,
};

Command::Command(const Util &util_in, GenericSocket &channel_in,
		bool raw_in, bool provide_checksum_in, bool request_checksum_in,
		bool dontwait_in, bool debug_in, bool verbose_in,
		unsigned int broadcast_group_mask_in, unsigned int multicast_burst_in, unsigned int sector_size_in) noexcept
	:
		util(util_in), channel(channel_in),
		raw(raw_in), provide_checksum(provide_checksum_in), request_checksum(request_checksum_in), dontwait(dontwait_in), debug(debug_in), verbose(verbose_in),
		broadcast_group_mask(broadcast_group_mask_in), multicast_burst(multicast_burst_in), sector_size(sector_size_in)


{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	prn.seed(tv.tv_usec);
}

void Command::read(const std::string &filename, int sector, int sectors) const
{
	int file_fd, offset, current, retries;
	struct timeval time_start, time_now;
	std::string send_string;
	std::string operation;
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	EVP_MD_CTX *hash_ctx;
	unsigned int hash_size;
	unsigned char hash[sha1_hash_size];
	std::string sha_local_hash_text;
	std::string sha_remote_hash_text;
	std::string data;

	if(filename.empty())
		throw(hard_exception("file name required"));

	if((file_fd = open(filename.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0666)) < 0)
		throw(hard_exception("can't create file"));

	try
	{
		gettimeofday(&time_start, 0);

		if(debug)
		{
			std::cout << "start read from 0x" << std::hex << sector * sector_size << " (" << std::dec << sector << ")";
			std::cout << ", length: 0x" << std::hex << sectors * sector_size << " (" << std::dec << sectors << ")";
			std::cout << std::endl;
		}

		hash_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(hash_ctx, EVP_sha1(), (ENGINE *)0);

		retries = 0;

		for(current = sector, offset = 0; current < (sector + sectors); current++)
		{
			retries += util.read_sector(sector_size, current, data);

			if(::write(file_fd, data.data(), data.length()) <= 0)
				throw(hard_exception("i/o error in write"));

			EVP_DigestUpdate(hash_ctx, (const unsigned char *)data.data(), data.length());

			offset += data.length();

			int seconds, useconds;
			double duration, rate;

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);
			rate = offset / 1024.0 / duration;

			std::cout << std::setfill(' ');
			std::cout << "received "	<< std::setw(3) << (offset / 1024) << " kbytes";
			std::cout << " in "			<< std::setw(5) << std::setprecision(2) << std::fixed << duration << " seconds";
			std::cout << " at rate "	<< std::setw(3) << std::setprecision(0) << std::fixed << rate << " kbytes/s";
			std::cout << ", received "	<< std::setw(3) << (current - sector) << " sectors";
			std::cout << ", retries "   << std::setw(2) << retries;
			std::cout << ", "			<< std::setw(3) << ((offset * 100) / (sectors * sector_size)) << "%       \r";
			std::cout.flush();
		}
	}
	catch(...)
	{
		std::cout << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	std::cout << std::endl << "checksumming " << sectors << " sectors from " << sector << "..." << std::endl;

	hash_size = sha1_hash_size;
	EVP_DigestFinal_ex(hash_ctx, hash, &hash_size);
	EVP_MD_CTX_free(hash_ctx);

	sha_local_hash_text = Util::sha1_hash_to_text(sha1_hash_size, hash);
	util.get_checksum(sector, sectors, sha_remote_hash_text);

	if(sha_local_hash_text != sha_remote_hash_text)
	{
		if(verbose)
		{
			std::cout << "! sector " << sector << "/" << sectors;
			std::cout << ", address: 0x" << std::hex << (sector * sector_size) << "/0x" << (sectors * sector_size) << std::dec << " read";
			std::cout << ", checksum failed";
			std::cout << ", local hash: " << sha_local_hash_text;
			std::cout << ", remote hash: " << sha_remote_hash_text;
			std::cout << std::endl;
		}

		throw(hard_exception("checksum read failed"));
	}

	std::cout << "checksum OK" << std::endl;
}

void Command::write(const std::string filename, int sector, bool simulate, bool otawrite) const
{
	int file_fd, length, current, offset, retries;
	struct timeval time_start, time_now;
	std::string send_string;
	std::string reply;
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	EVP_MD_CTX *hash_ctx;
	unsigned int hash_size;
	unsigned char hash[sha1_hash_size];
	std::string sha_local_hash_text;
	std::string sha_remote_hash_text;
	std::string data;
	unsigned int sectors_written, sectors_skipped, sectors_erased;
	unsigned char sector_buffer[sector_size];
	struct stat stat;

	if(filename.empty())
		throw(hard_exception("file name required"));

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	fstat(file_fd, &stat);
	length = (stat.st_size + (sector_size - 1)) / sector_size;

	sectors_skipped = 0;
	sectors_erased = 0;
	sectors_written = 0;
	offset = 0;

	try
	{
		gettimeofday(&time_start, 0);

		std::cout << "start ";

		if(simulate)
			std::cout << "simulate";
		else
		{
			if(otawrite)
				std::cout << "ota ";
			else
				std::cout << "normal ";

			std::cout << "write";
		}

		std::cout << " at address: 0x" << std::hex << std::setw(6) << std::setfill('0') << (sector * sector_size) << " (sector " << std::dec << sector << ")";
		std::cout << ", length: " << std::dec << std::setw(0) << (length * sector_size) << " (" << length << " sectors)";
		std::cout << std::endl;

		hash_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(hash_ctx, EVP_sha1(), (ENGINE *)0);

		retries = 0;

		for(current = sector; current < (sector + length); current++)
		{
			unsigned int attempt;

			memset(sector_buffer, 0xff, sector_size);

			if((::read(file_fd, sector_buffer, sector_size)) <= 0)
				throw(hard_exception("i/o error in read"));

			EVP_DigestUpdate(hash_ctx, sector_buffer, sector_size);

			for(attempt = 4; attempt > 0; attempt--)
			{
				try
				{
					retries += util.write_sector(current, std::string((const char *)sector_buffer, sizeof(sector_buffer)),
							sectors_written, sectors_erased, sectors_skipped, simulate);
				}
				catch(const transient_exception &e)
				{
					if(verbose)
						std::cerr << "command write: " << e.what() << ", try #" << attempt << std::endl;

					continue;
				}

				break;
			}

			if(attempt == 0)
				throw(hard_exception("command write: write sector: no more attempts"));

			offset += sector_size;

			int seconds, useconds;
			double duration, rate;

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);
			rate = offset / 1024.0 / duration;

			std::cout << std::setfill(' ');
			std::cout << "sent "		<< std::setw(4) << (offset / 1024) << " kbytes";
			std::cout << " in "			<< std::setw(5) << std::setprecision(2) << std::fixed << duration << " seconds";
			std::cout << " at rate "	<< std::setw(4) << std::setprecision(0) << std::fixed << rate << " kbytes/s";
			std::cout << ", sent "		<< std::setw(3) << (current - sector + 1) << " sectors";
			std::cout << ", written "	<< std::setw(3) << sectors_written << " sectors";
			std::cout << ", erased "	<< std::setw(3) << sectors_erased << " sectors";
			std::cout << ", skipped "	<< std::setw(3) << sectors_skipped << " sectors";
			std::cout << ", retries "   << std::setw(2) << retries;
			std::cout << ", "			<< std::setw(3) << (((offset + sector_size) * 100) / (length * sector_size)) << "%       \r";
			std::cout.flush();
		}
	}
	catch(...)
	{
		std::cout << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	std::cout << std::endl;

	if(simulate)
		std::cout << "simulate finished" << std::endl;
	else
	{
		std::cout << "checksumming " << length << " sectors..." << std::endl;

		hash_size = sha1_hash_size;
		EVP_DigestFinal_ex(hash_ctx, hash, &hash_size);
		EVP_MD_CTX_free(hash_ctx);

		sha_local_hash_text = Util::sha1_hash_to_text(sha1_hash_size, hash);

		util.get_checksum(sector, length, sha_remote_hash_text);

		if(debug)
		{
			std::cout << std::endl << "local checksum:  " << sha_local_hash_text << std::endl;
			std::cout << std::endl << "remote checksum: " << sha_remote_hash_text << std::endl;
		}

		if(sha_local_hash_text != sha_remote_hash_text)
			throw(hard_exception(boost::format("checksum failed: SHA hash differs, local: %u, remote: %s") % sha_local_hash_text % sha_remote_hash_text));

		std::cout << "checksum OK" << std::endl;
		std::cout << "write finished" << std::endl;
	}
}

void Command::verify(const std::string &filename, int sector) const
{
	int file_fd, offset;
	int current, sectors;
	struct timeval time_start, time_now;
	std::string send_string;
	std::string operation;
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	std::string local_data, remote_data;
	struct stat stat;
	uint8_t sector_buffer[sector_size];
	int retries;

	if(filename.empty())
		throw(hard_exception("file name required"));

	if((file_fd = open(filename.c_str(), O_RDONLY)) < 0)
		throw(hard_exception("can't open file"));

	fstat(file_fd, &stat);
	sectors = (stat.st_size + (sector_size - 1)) / sector_size;
	offset = 0;

	try
	{
		gettimeofday(&time_start, 0);

		if(debug)
		{
			std::cout << "start verify from 0x" << std::hex << sector * sector_size << " (" << std::dec << sector << ")";
			std::cout << ", length: 0x" << std::hex << sectors * sector_size << " (" << std::dec << sectors << ")";
			std::cout << std::endl;
		}

		retries = 0;

		for(current = sector; current < (sector + sectors); current++)
		{
			memset(sector_buffer, 0xff, sector_size);

			if(::read(file_fd, sector_buffer, sizeof(sector_buffer)) <= 0)
				throw(hard_exception("i/o error in read"));

			local_data.assign((const char *)sector_buffer, sizeof(sector_buffer));

			retries += util.read_sector(sector_size, current, remote_data);

			if(local_data != remote_data)
				throw(hard_exception(boost::format("data mismatch, sector %u") % current));

			offset += sizeof(sector_buffer);

			int seconds, useconds;
			double duration, rate;

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);
			rate = offset / 1024.0 / duration;

			std::cout << std::setfill(' ');
			std::cout << "received "	<< std::setw(3) << (offset / 1024) << " kbytes";
			std::cout << " in "			<< std::setw(5) << std::setprecision(2) << std::fixed << duration << " seconds";
			std::cout << " at rate "	<< std::setw(3) << std::setprecision(0) << std::fixed << rate << " kbytes/s";
			std::cout << ", received "	<< std::setw(3) << (current - sector) << " sectors";
			std::cout << ", retries "   << std::setw(2) << retries;
			std::cout << ", "			<< std::setw(3) << ((offset * 100) / (sectors * sector_size)) << "%       \r";
			std::cout.flush();
		}
	}
	catch(...)
	{
		std::cout << std::endl;
		close(file_fd);
		throw;
	}

	close(file_fd);

	std::cout << std::endl << "verify OK" << std::endl;
}

void Command::benchmark(int length) const
{
	unsigned int phase, retries, iterations, current;
	std::string command;
	std::string data(sector_size, '\0');
	std::string expect;
	std::string reply;
	struct timeval time_start, time_now;
	int seconds, useconds;
	double duration, rate;

	iterations = 1024;

	for(phase = 0; phase < 2; phase++)
	{
		retries = 0;

		gettimeofday(&time_start, 0);

		for(current = 0; current < iterations; current++)
		{
			if(phase == 0)
				retries += util.process("flash-bench 0",
						&data,
						reply,
						nullptr,
						"OK flash-bench: sending 0 bytes");
			else
				retries += util.process(std::string("flash-bench ") + std::to_string(length),
						nullptr,
						reply,
						&data,
						(std::string("OK flash-bench: sending ") + std::to_string(length) + " bytes").c_str());

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);
			rate = current * 4.0 / duration;

			std::cout << std::setfill(' ');
			std::cout << ((phase == 0) ? "sent     " : "received ");
			std::cout << std::setw(4) << (current * sector_size / 1024) << " kbytes";
			std::cout << " in "			<< std::setw(5) << std::setprecision(2) << std::fixed << duration << " seconds";
			std::cout << " at rate "	<< std::setw(4) << std::setprecision(0) << std::fixed << rate << " kbytes/s";
			std::cout << ", sent "		<< std::setw(4) << (current + 1) << " sectors";
			std::cout << ", retries "	<< std::setw(2) << retries;
			std::cout << ", "			<< std::setw(3) << (((current + 1) * 100) / iterations) << "%       \r";
			std::cout.flush();
		}

		usleep(200000);
		std::cout << std::endl;
	}
}

void Command::image_send_sector(int current_sector, const std::string &data,
		unsigned int current_x, unsigned int current_y, unsigned int depth) const
{
	std::string command;
	std::string reply;
	unsigned int pixels;

	if(current_sector < 0)
	{
		switch(depth)
		{
			case(1):
			{
				pixels = data.length() * 8;
				break;
			}

			case(16):
			{
				pixels = data.length() / 2;
				break;
			}

			case(24):
			{
				pixels = data.length() / 3;
				break;
			}

			default:
			{
				throw(hard_exception("unknown display colour depth"));
			}
		}

		command = (boost::format("display-plot %u %u %u\n") % pixels % current_x % current_y).str();
		util.process(command, &data, reply, nullptr, "display plot success: yes");
	}
	else
	{
		unsigned int sectors_written, sectors_erased, sectors_skipped;
		std::string pad;
		unsigned int pad_length = 4096 - data.length();
		unsigned int attempt;

		pad.assign(pad_length, 0x00);

		for(attempt = 4; attempt > 0; attempt--)
		{
			try
			{
				util.write_sector(current_sector, data + pad, sectors_written, sectors_erased, sectors_skipped, false);
			}
			catch(const transient_exception &e)
			{
				if(verbose)
					std::cerr << "command image send sector: " << e.what() << std::endl;

				continue;
			}

			break;
		}

		if(attempt == 0)
			throw(hard_exception("command image send sector: write sector: no more attempts"));
	}
}

void Command::image(int image_slot, const std::string &filename,
		unsigned int dim_x, unsigned int dim_y, unsigned int depth, int image_timeout) const
{
	struct timeval time_start, time_now;
	int current_sector;

	gettimeofday(&time_start, 0);

	if(image_slot == 0)
		current_sector = 0x200000 / sector_size;
	else
		if(image_slot == 1)
			current_sector = 0x280000 / sector_size;
		else
			current_sector = -1;

	try
	{
		Magick::InitializeMagick(nullptr);

		Magick::Image image;
		Magick::Geometry newsize(dim_x, dim_y);
		Magick::Color colour;
		const Magick::Quantum *pixel_cache;

		std::string reply;
		unsigned char sector_buffer[sector_size];
		unsigned int start_x, start_y;
		unsigned int current_buffer, x, y;
		double r, g, b;
		int seconds, useconds;
		double duration, rate;

		newsize.aspect(true);

		if(!filename.length())
			throw(hard_exception("empty file name"));

		image.read(filename);

		image.type(MagickCore::TrueColorType);

		if(debug)
			std::cout << "image loaded from " << filename << ", " << image.columns() << "x" << image.rows() << ", " << image.magick() << std::endl;

		image.filterType(Magick::TriangleFilter);
		image.resize(newsize);

		if((image.columns() != dim_x) || (image.rows() != dim_y))
			throw(hard_exception("image magic resize failed"));

		image.modifyImage();

		pixel_cache = image.getPixels(0, 0, dim_x, dim_y);

		if(image_slot < 0)
			util.process(std::string("display-freeze ") + std::to_string(10000), nullptr, reply, nullptr,
					"display freeze success: yes");

		current_buffer = 0;
		start_x = 0;
		start_y = 0;

		memset(sector_buffer, 0xff, sector_size);

		for(y = 0; y < dim_y; y++)
		{
			for(x = 0; x < dim_x; x++)
			{
				r = pixel_cache[(((y * dim_x) + x) * 3) + 0] / (1 << MAGICKCORE_QUANTUM_DEPTH);
				g = pixel_cache[(((y * dim_x) + x) * 3) + 1] / (1 << MAGICKCORE_QUANTUM_DEPTH);
				b = pixel_cache[(((y * dim_x) + x) * 3) + 2] / (1 << MAGICKCORE_QUANTUM_DEPTH);

				switch(depth)
				{
					case(1):
					{
						if((current_buffer / 8) + 1 > sector_size)
						{
							image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer / 8), start_x, start_y, depth);
							memset(sector_buffer, 0xff, sector_size);
							current_buffer -= (current_buffer / 8) * 8;
						}

						if((r + g + b) > (3 / 2))
							sector_buffer[current_buffer / 8] |=  (1 << (7 - (current_buffer % 8)));
						else
							sector_buffer[current_buffer / 8] &= ~(1 << (7 - (current_buffer % 8)));

						current_buffer++;

						break;
					}

					case(16):
					{
						unsigned int ru16, gu16, bu16;
						unsigned int r1, g1, g2, b1;

						if((current_buffer + 2) > sector_size)
						{
							image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer), start_x, start_y, depth);
							memset(sector_buffer, 0xff, sector_size);

							if(current_sector >= 0)
								current_sector++;

							current_buffer = 0;
							start_x = x;
							start_y = y;
						}

						ru16 = r * ((1 << 5) - 1);
						gu16 = g * ((1 << 6) - 1);
						bu16 = b * ((1 << 5) - 1);

						r1 = (ru16 & 0b00011111) >> 0;
						g1 = (gu16 & 0b00111000) >> 3;
						g2 = (gu16 & 0b00000111) >> 0;
						b1 = (bu16 & 0b00011111) >> 0;

						sector_buffer[current_buffer++] = (r1 << 3) | (g1 >> 0);
						sector_buffer[current_buffer++] = (g2 << 5) | (b1 >> 0);

						break;
					}

					case(24):
					{
						if((current_buffer + 3) > sector_size)
						{
							image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer), start_x, start_y, depth);
							memset(sector_buffer, 0xff, sector_size);

							if(current_sector >= 0)
								current_sector++;

							current_buffer = 0;
							start_x = x;
							start_y = y;
						}

						sector_buffer[current_buffer++] = r * ((1 << 8) - 1);
						sector_buffer[current_buffer++] = g * ((1 << 8) - 1);
						sector_buffer[current_buffer++] = b * ((1 << 8) - 1);

						break;
					}
				}
			}

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);
			rate = (x * 2 * y) / 1024.0 / duration;

			std::cout << std::setfill(' ');
			std::cout << "sent "		<< std::setw(4) << ((x * 2 * y) / 1024) << " kbytes";
			std::cout << " in "			<< std::setw(5) << std::setprecision(2) << std::fixed << duration << " seconds";
			std::cout << " at rate "	<< std::setw(4) << std::setprecision(0) << std::fixed << rate << " kbytes/s";
			std::cout << ", x "			<< std::setw(3) << x;
			std::cout << ", y "			<< std::setw(3) << y;
			std::cout << ", "			<< std::setw(3) << (x * y * 100) / (dim_x * dim_y) << "%       \r";
			std::cout.flush();
		}

		if(current_buffer > 0)
		{
			if(depth == 1)
			{
				if(current_buffer % 8)
					current_buffer += 8;

				current_buffer /= 8;
			}

			image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer), start_x, start_y, depth);
		}

		std::cout << std::endl;

		if(image_slot < 0)
			util.process(std::string("display-freeze ") + std::to_string(0), nullptr, reply, nullptr,
					"display freeze success: yes");

		if((image_slot < 0) && (image_timeout > 0))
			util.process(std::string("display-freeze ") + std::to_string(image_timeout), nullptr, reply, nullptr,
					"display freeze success: yes");
	}
	catch(const Magick::Error &error)
	{
		throw(hard_exception(boost::format("image: load failed: %s") % error.what()));
	}
	catch(const Magick::Warning &warning)
	{
		std::cout << "image: " << warning.what();
	}
}

void Command::cie_spi_write(const std::string &data, const char *match) const
{
	std::string reply;

	util.process(data, nullptr, reply, nullptr, match);
}

void Command::cie_uc_cmd_data(bool isdata, unsigned int data_value) const
{
	std::string data, reply;
	std::stringstream text;

	text.str("");
	text << "spt 17 8 " << std::hex << std::setfill('0') << std::setw(2) << data_value << " 0 0 0 0";
	data = text.str();

	cie_spi_write("sps", "spi start ok");
	cie_spi_write(std::string("iw 1 0 ") + (isdata ? "1" : "0"), (std::string("digital output: \\[") + (isdata ? "1" : "0") + "\\]").c_str());
	cie_spi_write(data, "spi transmit ok");
	cie_spi_write("spf", "spi finish ok");
}

void Command::cie_uc_cmd(unsigned int cmd) const
{
	return(cie_uc_cmd_data(false, cmd));
}

void Command::cie_uc_data(unsigned int data) const
{
	return(cie_uc_cmd_data(true, data));
}

void Command::cie_uc_data_string(const std::string valuestring) const
{
	cie_spi_write("iw 1 0 1", "digital output: \\[1\\]");
	cie_spi_write("sps", "spi start ok");
	cie_spi_write(std::string("spw 8 ") + valuestring, "spi write ok");
	cie_spi_write("spt 17 0 0 0 0 0 0 0", "spi transmit ok");
	cie_spi_write("spf", "spi finish ok");
}

void Command::image_epaper(const std::string &filename) const
{
	static const unsigned int dim_x = 212;
	static const unsigned int dim_y = 104;
	uint8_t dummy_display[dim_x][dim_y];
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	std::string values, command, reply;
	std::stringstream text;
	unsigned int layer, all_bytes, bytes, byte, bit;
	int x, y;
	struct timeval time_start, time_now;
	int seconds, useconds;
	double duration, rate;

	gettimeofday(&time_start, 0);

	cie_spi_write("spc 0 0", "spi configure ok");

	cie_uc_cmd(0x04); 	// power on PON, no arguments

	cie_uc_cmd(0x00);	// panel settings PSR, 1 argument
	cie_uc_data(0x0f);	// default

	cie_uc_cmd(0x61); 	// resultion settings TSR, 3 argument
	cie_uc_data(0x68);	// height
	cie_uc_data(0x00);	// width[7]
	cie_uc_data(0xd4);	// width[6-0]

	cie_uc_cmd(0x50); 	// vcom and data interval setting, 1 argument
	cie_uc_data(0xd7);	// default

	try
	{
		Magick::Image image;
		Magick::Geometry newsize(dim_x, dim_y);
		Magick::Color colour;
		newsize.aspect(true);

		if(!filename.length())
			throw(hard_exception("image epaper: empty file name"));

		image.read(filename);

		if(debug)
			std::cout << "image loaded from " << filename << ", " << image.columns() << "x" << image.rows() << ", " << image.magick() << std::endl;

		image.resize(newsize);

		if((image.columns() != dim_x) || (image.rows() != dim_y))
			throw(hard_exception("image epaper: image magic resize failed"));

		all_bytes = 0;
		bytes = 0;
		byte = 0;
		bit = 7;
		values = "";
		cie_spi_write("sps", "spi start ok");

		for(x = 0; x < (int)dim_x; x++)
			for(y = 0; y < (int)dim_y; y++)
				dummy_display[x][y] = 0;

		for(layer = 0; layer < 2; layer++)
		{
			cie_uc_cmd(layer == 0 ? 0x10 : 0x13); // DTM1 / DTM2

			for(x = dim_x - 1; x >= 0; x--)
			{
				for(y = 0; y < (int)dim_y; y++)
				{
					colour = image.pixelColor(x, y);

					if(layer == 0)
					{
						//if((colour.quantumRed() > 16384) && (colour.quantumGreen() > 16384) && (colour.quantumBlue() > 16384)) // FIXME
						//{
							//dummy_display[x][y] |= 0x01;
							//byte |= 1 << bit;
						//}
					}
					else
					{
						//if((colour.quantumRed() > 16384) && (colour.quantumGreen() < 16384) && (colour.quantumBlue() < 16384)) // FIXME
						//{
							//dummy_display[x][y] |= 0x02;
							//byte |= 1 << bit;
						//}
					}

					if(bit > 0)
						bit--;
					else
					{
						text.str("");
						text << std::hex << std::setfill('0') << std::setw(2) << byte << " ";
						values.append(text.str());
						all_bytes++;
						bytes++;
						bit = 7;
						byte = 0;

						if(bytes > 31)
						{
							cie_uc_data_string(values);
							values = "";
							bytes = 0;
						}
					}
				}

				gettimeofday(&time_now, 0);

				seconds = time_now.tv_sec - time_start.tv_sec;
				useconds = time_now.tv_usec - time_start.tv_usec;
				duration = seconds + (useconds / 1000000.0);
				rate = all_bytes / 1024.0 / duration;

				std::cout << std::setfill(' ');
				std::cout << "sent "		<< std::setw(4) << (all_bytes / 1024) << " kbytes";
				std::cout << " in "			<< std::setw(5) << std::setprecision(2) << std::fixed << duration << " seconds";
				std::cout << " at rate "	<< std::setw(4) << std::setprecision(0) << std::fixed << rate << " kbytes/s";
				std::cout << ", x "			<< std::setw(3) << x;
				std::cout << ", y "			<< std::setw(3) << y;
				std::cout << ", "			<< std::setw(3) << ((dim_x - 1 - x) * y * 100) / (2 * dim_x * dim_y) << "%       \r";
				std::cout.flush();
			}

			if(bytes > 0)
			{
				cie_uc_data_string(values);
				values = "";
				bytes = 0;
			}

			cie_uc_cmd(0x11); // data stop DST
		}

		cie_uc_cmd(0x12); // display refresh DRF
	}
	catch(const Magick::Error &error)
	{
		throw(hard_exception(std::string("image epaper: load failed: ") + error.what()));
	}
	catch(const Magick::Warning &warning)
	{
		std::cout << "image epaper: " << warning.what();
	}

	if(debug)
	{
		for(y = 0; y < 104; y++)
		{
			for(x = 0; x < 200; x++)
			{
				switch(dummy_display[x][y])
				{
					case(0): fputs(" ", stdout); break;
					case(1): fputs("1", stdout); break;
					case(2): fputs("2", stdout); break;
					default: fputs("*", stdout); break;
				}
			}

			fputs("$\n", stdout);
		}
	}
}

void Command::send(std::string args) const
{
	std::string arg;
	size_t current;
	Packet send_packet;
	std::string send_data;
	Packet receive_packet;
	std::string receive_data;
	std::string reply;
	std::string reply_oob;
	int retries;

	if(dontwait)
	{
		if(daemon(0, 0))
		{
			perror("daemon");
			return;
		}
	}

	while(args.length() > 0)
	{
		if((current = args.find('\n')) != std::string::npos)
		{
			arg = args.substr(0, current);
			args.erase(0, current + 1);
		}
		else
		{
			arg = args;
			args.clear();
		}

		retries = util.process(arg, nullptr, reply, &reply_oob);

		std::cout << reply;

		if(reply_oob.length() > 0)
		{
			unsigned int length = 0;

			std::cout << std::endl << reply_oob.length() << " bytes of OOB data:";

			for(const auto &it : reply_oob)
			{
				if((length++ % 20) == 0)
					std::cout << std::endl << "    ";

				std::cout << (boost::format("0x%02x ") % (((unsigned int)it) & 0xff));
			}

			std::cout << std::endl;
		}
		else
			std::cout << std::endl;

		if(retries > 0)
			std::cout << retries << " retries" << std::endl;
	}
}

void Command::multicast(const std::string &args)
{
	Packet send_packet(&args, nullptr);
	Packet receive_packet;
	std::string send_data;
	std::string receive_data;
	std::string reply_data;
	std::string packet;
	struct timeval tv_start, tv_now;
	uint64_t start, now;
	struct sockaddr_in remote_host;
	char host_buffer[64];
	char service[64];
	std::string hostname;
	int gai_error;
	std::string reply;
	std::string info;
	std::string line;
	uint32_t host_id;
	typedef struct { int count; std::string hostname; std::string text; } multicast_reply_t;
	typedef std::map<unsigned uint32_t, multicast_reply_t> multicast_replies_t;
	multicast_replies_t multicast_replies;
	int total_replies, total_hosts;
	int run;
	uint32_t transaction_id;

	transaction_id = prn();
	packet = send_packet.encapsulate(raw, provide_checksum, request_checksum, broadcast_group_mask, &transaction_id);

	if(dontwait)
	{
		for(run = 0; run < (int)multicast_burst; run++)
		{
			send_data = packet;
			channel.send(send_data);
			usleep(100000);
		}

		return;
	}

	total_replies = total_hosts = 0;

	gettimeofday(&tv_start, nullptr);
	start = (tv_start.tv_sec * 1000000) + tv_start.tv_usec;

	for(run = 0; run < (int)multicast_burst; run++)
	{
		gettimeofday(&tv_now, nullptr);
		now = (tv_now.tv_sec * 1000000) + tv_now.tv_usec;

		if(((now - start) / 1000ULL) > 10000)
			break;

		send_data = packet;
		channel.send(send_data, 100);

		for(;;)
		{
			reply_data.clear();

			if(!channel.receive(reply_data, 100, &remote_host))
				break;

			receive_packet.clear();
			receive_packet.append_data(reply_data);

			if(!receive_packet.decapsulate(&reply_data, nullptr, verbose, nullptr, &transaction_id))
			{
				if(verbose)
					std::cout << "multicast: cannot decapsulate" << std::endl;

				continue;
			}

			host_id = ntohl(remote_host.sin_addr.s_addr);

			gai_error = getnameinfo((struct sockaddr *)&remote_host, sizeof(remote_host), host_buffer, sizeof(host_buffer),
					service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NOFQDN);

			if(gai_error != 0)
			{
				if(verbose)
					std::cout << "cannot resolve: " << gai_strerror(gai_error) << std::endl;

				hostname = "0.0.0.0";
			}
			else
				hostname = host_buffer;

			total_replies++;

			auto it = multicast_replies.find(host_id);

			if(it != multicast_replies.end())
				it->second.count++;
			else
			{
				total_hosts++;
				multicast_reply_t entry;

				entry.count = 1;
				entry.hostname = hostname;
				entry.text = reply_data;
				multicast_replies[host_id] = entry;
			}
		}
	}

	for(auto &it : multicast_replies)
	{
		std::string host_id_text;

		host_id_text += std::to_string(((it.first & 0xff000000) >> 24)) + ".";
		host_id_text += std::to_string(((it.first & 0x00ff0000) >> 16)) + ".";
		host_id_text += std::to_string(((it.first & 0x0000ff00) >>  8)) + ".";
		host_id_text += std::to_string(((it.first & 0x000000ff) >>  0));
		std::cout << std::setw(12) << std::left << host_id_text;
		std::cout << " " << std::setw(2) << std::right << it.second.count << " ";
		std::cout << std::setw(12) << std::left << it.second.hostname;
		std::cout << " " << it.second.text;
		std::cout << std::endl;
	}

	std::cout << std::endl << multicast_burst << " probes sent, " << total_replies << " replies received, " << total_hosts << " hosts" << std::endl;
}

void Command::commit_ota(unsigned int flash_slot, unsigned int sector, bool reset, bool notemp) const
{
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	std::string send_data;
	Packet packet;
	static const char *flash_select_expect = "OK flash-select: slot ([0-9]+) selected, sector ([0-9]+), permanent ([0-1])";

	send_data = (boost::format("flash-select %u %u") % flash_slot % (notemp ? 1 : 0)).str();
	util.process(send_data, nullptr, reply, nullptr, flash_select_expect, &string_value, &int_value);

	if(int_value[0] != (int)flash_slot)
		throw(hard_exception(boost::format("flash-select failed, local slot (%u) != remote slot (%u)") % flash_slot % int_value[0]));

	if(int_value[1] != (int)sector)
		throw(hard_exception("flash-select failed, local sector != remote sector"));

	if(int_value[2] != notemp ? 1 : 0)
		throw(hard_exception("flash-select failed, local permanent != remote permanent"));

	std::cout << "selected ";

	if(!notemp)
		std::cout << "one time";

	std::cout << " boot slot" << std::endl;

	if(!reset)
		return;

	std::cout << "rebooting... ";

	packet.clear();
	packet.append_data("reset\n");
	send_data = packet.encapsulate(raw, provide_checksum, request_checksum, broadcast_group_mask);
	channel.send(send_data);

	for(unsigned int ix = 0; ix < 30; ix++)
	{
		try
		{
			channel.disconnect();
			channel.connect();
			util.process("flash-info", nullptr, reply, nullptr, flash_info_expect, &string_value, &int_value);
		}
		catch(const transient_exception &e)
		{
			if(verbose)
				std::cerr << e.what();
			else
			{
				std::cout << ix << " ";
				std::flush(std::cout);
			}

			usleep(100000);
			continue;
		}

		break;
	}

	std::cout << std::endl;

	std::cout << "reboot finished" << std::endl;

	util.process("flash-info", nullptr, reply, nullptr, flash_info_expect, &string_value, &int_value);

	if(int_value[0] != (int)flash_slot)
		throw(hard_exception(boost::format("boot failed, requested slot (%u) != active slot (%u)") % flash_slot % int_value[0]));

	if(!notemp)
	{
		std::cout << "boot succeeded, permanently selecting boot slot: " << flash_slot << std::endl;

		send_data = (boost::format("flash-select %u 1") % flash_slot).str();
		util.process(send_data, nullptr, reply, nullptr, flash_select_expect, &string_value, &int_value);

		if(int_value[0] != (int)flash_slot)
			throw(hard_exception(boost::format("flash-select failed, local slot (%u) != remote slot (%u)") % flash_slot % int_value[0]));

		if(int_value[1] != (int)sector)
			throw(hard_exception("flash-select failed, local sector != remote sector"));

		if(int_value[2] != 1)
			throw(hard_exception("flash-select failed, local permanent != remote permanent"));
	}

	util.process("stats", nullptr, reply, nullptr, "\\s*>\\s*firmware\\s*>\\s*date:\\s*([a-zA-Z0-9: ]+).*", &string_value, &int_value);
	std::cout << "firmware version: " << string_value[0] << std::endl;
}
