#include "e32if.h"
#include "exception.h"
#include "packet.h"
#include "ip_socket.h"
#include "bt_socket.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <string>
#include <iostream>
#include <boost/format.hpp>
#include <openssl/evp.h>
#include <Magick++.h>
#include <iostream>
#include <string>
#include <vector>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

enum
{
	flash_sector_size = 4096,
};

E32If::E32If(const std::vector<std::string> &args)
{
	start(args);
}

E32If::E32If(int argc, const char * const *argv)
{
	int ix;
	std::vector<std::string> args;

	for(ix = 1; ix < argc; ix++)
		args.push_back(std::string(argv[ix]));

	start(args);
}

E32If::E32If(const std::string &args)
{
	std::vector<std::string> args_split;

	args_split = po::split_unix(args);

	start(args_split);
}

E32If::~E32If()
{
	delete util;
	delete channel;
}

void E32If::start(const std::vector<std::string> &argv)
{
	po::options_description	options("e32if usage");

	try
	{
		bool option_raw = false;
		bool option_verbose = false;
		bool option_debug = false;
		bool option_no_provide_checksum = false;
		bool option_no_request_checksum = false;
		bool option_dontwait = false;
		unsigned int option_broadcast_group_mask = 0;
		unsigned int option_multicast_burst = 1;
		std::vector<std::string> host_args;
		std::string host;
		std::string args;
		std::string command_port;
		std::string filename;
		std::string start_string;
		std::string length_string;
		std::string transport;
		int start;
		int image_slot;
		int image_timeout;
		int dim_x, dim_y, depth;
		unsigned int length;
		bool nocommit = false;
		bool noreset = false;
		bool notemp = false;
		bool otawrite = false;
		bool cmd_write = false;
		bool cmd_ota = false;
		bool cmd_simulate = false;
		bool cmd_verify = false;
		bool cmd_benchmark = false;
		bool cmd_image = false;
		bool cmd_image_epaper = false;
		bool cmd_broadcast = false;
		bool cmd_multicast = false;
		bool cmd_read = false;
		bool cmd_info = false;
		bool cmd_write_file = false;
		bool cmd_read_file = false;
		unsigned int selected;
		config_transport_t transport_type;

		transport = "udp";

		options.add_options()
			("info,i",					po::bool_switch(&cmd_info)->implicit_value(true),							"INFO")
			("read,R",					po::bool_switch(&cmd_read)->implicit_value(true),							"READ")
			("verify,V",				po::bool_switch(&cmd_verify)->implicit_value(true),							"VERIFY")
			("simulate,S",				po::bool_switch(&cmd_simulate)->implicit_value(true),						"WRITE simulate")
			("write,W",					po::bool_switch(&cmd_write)->implicit_value(true),							"WRITE")
			("ota,O",					po::bool_switch(&cmd_ota)->implicit_value(true),							"OTA write (esp32)")
			("write-file,w",			po::bool_switch(&cmd_write_file)->implicit_value(true),						"WRITE FILE to littlefs on ESP32")
			("read-file,a",				po::bool_switch(&cmd_read_file)->implicit_value(true),						"READ FILE from littlefs on ESP32")
			("benchmark,B",				po::bool_switch(&cmd_benchmark)->implicit_value(true),						"BENCHMARK")
			("image,I",					po::bool_switch(&cmd_image)->implicit_value(true),							"SEND IMAGE")
			("epaper-image,e",			po::bool_switch(&cmd_image_epaper)->implicit_value(true),					"SEND EPAPER IMAGE (uc8151d connected to host)")
			("broadcast,b",				po::bool_switch(&cmd_broadcast)->implicit_value(true),						"BROADCAST SENDER send broadcast message")
			("multicast,M",				po::bool_switch(&cmd_multicast)->implicit_value(true),						"MULTICAST SENDER send multicast message")
			("host,h",					po::value<std::vector<std::string> >(&host_args)->required(),				"host or broadcast address or multicast group to use")
			("verbose,v",				po::bool_switch(&option_verbose)->implicit_value(true),						"verbose output")
			("debug,D",					po::bool_switch(&option_debug)->implicit_value(true),						"packet trace etc.")
			("transport,t",				po::value<std::string>(&transport),											"select transport: udp (default), tcp or bluetooth (bt)")
			("filename,f",				po::value<std::string>(&filename),											"file name")
			("start,s",					po::value<std::string>(&start_string)->default_value("-1"),					"send/receive start address (OTA is default)")
			("length,l",				po::value<std::string>(&length_string)->default_value("1"),					"read length")
			("command-port,p",			po::value<std::string>(&command_port)->default_value("24"),					"command port to connect to")
			("nocommit,n",				po::bool_switch(&nocommit)->implicit_value(true),							"don't commit after writing")
			("noreset,N",				po::bool_switch(&noreset)->implicit_value(true),							"don't reset after commit")
			("notemp,T",				po::bool_switch(&notemp)->implicit_value(true),								"don't commit temporarily, commit to flash")
			("dontwait,d",				po::bool_switch(&option_dontwait)->implicit_value(true),					"don't wait for reply on message")
			("image_slot,x",			po::value<int>(&image_slot)->default_value(-1),								"send image to flash slot x instead of frame buffer")
			("image_timeout,y",			po::value<int>(&image_timeout)->default_value(5000),						"freeze frame buffer for y ms after sending")
			("no-provide-checksum,1",	po::bool_switch(&option_no_provide_checksum)->implicit_value(true),			"do not provide checksum")
			("no-request-checksum,2",	po::bool_switch(&option_no_request_checksum)->implicit_value(true),			"do not request checksum")
			("raw,r",					po::bool_switch(&option_raw)->implicit_value(true),							"do not use packet encapsulation")
			("broadcast-groups,g",		po::value<unsigned int>(&option_broadcast_group_mask)->default_value(0),	"select broadcast groups (bitfield)")
			("burst,u",					po::value<unsigned int>(&option_multicast_burst)->default_value(1),			"burst broadcast and multicast packets multiple times");

		po::positional_options_description positional_options;
		positional_options.add("host", -1);

		po::variables_map varmap;
		auto parsed = po::command_line_parser(argv).options(options).positional(positional_options).run();
		po::store(parsed, varmap);
		po::notify(varmap);

		auto it = host_args.begin();
		host = *(it++);
		auto it1 = it;

		for(; it != host_args.end(); it++)
		{
			if(it != it1)
				args.append(" ");

			args.append(*it);
		}

		if((host.length() == 17) && (host.at(2) == ':') && (host.at(5) == ':') && (host.at(8) == ':') && (host.at(11) == ':') && (host.at(14) == ':'))
			transport = "bluetooth";

		if(option_broadcast_group_mask)
		{
			cmd_broadcast = true;
			transport = "udp";
		}

		selected = 0;

		if(cmd_read)
			selected++;

		if(cmd_write)
			selected++;

		if(cmd_ota)
			selected++;

		if(cmd_read_file)
			selected++;

		if(cmd_write_file)
			selected++;

		if(cmd_simulate)
			selected++;

		if(cmd_verify)
			selected++;

		if(cmd_benchmark)
			selected++;

		if(cmd_image)
			selected++;

		if(cmd_image_epaper)
			selected++;

		if(cmd_info)
			selected++;

		if(cmd_broadcast)
			selected++;

		if(cmd_multicast)
			selected++;

		if(selected > 1)
			throw(hard_exception("specify one of ota/write/simulate/verify/image/epaper-image/read/info"));

		if((transport == "bt") || (transport == "bluetooth"))
			transport_type = transport_bluetooth;
		else
			if(transport == "tcp")
				transport_type = transport_tcp_ip;
			else
				if(transport == "udp")
					transport_type = transport_udp_ip;
				else
					throw(hard_exception("unknown transport, use bluetooth/bt, udp or ip"));

		config = E32IfConfig
		{
			.host = host,
			.command_port = command_port,
			.transport = transport_type,
			.broadcast = cmd_broadcast,
			.multicast = cmd_multicast,
			.debug = option_debug,
			.verbose = option_verbose,
			.dontwait = option_dontwait,
			.broadcast_group_mask = option_broadcast_group_mask,
			.multicast_burst = option_multicast_burst,
			.raw = option_raw,
			.provide_checksum = !option_no_provide_checksum,
			.request_checksum = !option_no_request_checksum
		};

		struct timeval tv;
		gettimeofday(&tv, nullptr);
		prn.seed(tv.tv_usec);

		switch(config.transport)
		{
			case(transport_tcp_ip):
			case(transport_udp_ip):
			{
				channel = new IPSocket(config);
				break;
			}

			case(transport_bluetooth):
			{
				channel = new BTSocket(config);
				break;
			}

			default:
			{
				throw(hard_exception("e32if: unknown transport"));
			}
		}

		util = new Util(channel, config);
		channel->connect();

		if(selected == 0)
			std::cout << this->send(args);
		else
		{
			if(cmd_broadcast || cmd_multicast)
				std::cout << this->multicast(args);
			else
			{
				start = -1;

				try
				{
					start = std::stoi(start_string, 0, 0);
				}
				catch(const std::invalid_argument &)
				{
					throw(hard_exception("invalid value for start argument"));
				}
				catch(const std::out_of_range &)
				{
					throw(hard_exception("invalid value for start argument"));
				}

				try
				{
					length = std::stoi(length_string, 0, 0);
				}
				catch(const std::invalid_argument &)
				{
					throw(hard_exception("invalid value for length argument"));
				}
				catch(const std::out_of_range &)
				{
					throw(hard_exception("invalid value for length argument"));
				}

				std::string reply;
				std::vector<int> int_value;
				std::vector<std::string> string_value;
				std::string platform;
				unsigned int flash_slot_current, flash_slot_next, flash_address[2];

				try
				{
					this->process("flash-info", "", reply, nullptr,
							"OK (flash function|esp32 ota) available, slots: 2, current: ([0-9])(?:, next: ([0-9]))?, sectors: \\[ ([0-9]+), ([0-9]+) \\], display: ([0-9]+)x([0-9]+)px@([0-9]+)",
							&string_value, &int_value);
				}
				catch(const e32if_exception &e)
				{
					throw(hard_exception(boost::format("flash incompatible image: %s") % e.what()));
				}

				if(string_value[0] == "esp32 ota")
				{
					platform = "esp32";

					flash_slot_current = int_value[1];
					flash_slot_next = int_value[2];
					flash_address[0] = int_value[3];
					flash_address[1] = int_value[4];
					dim_x = int_value[5];
					dim_y = int_value[6];
					depth = int_value[7];
				}
				else
				{
					platform = "esp8266";

					flash_slot_current = int_value[1];
					flash_address[0] = int_value[3];
					flash_address[1] = int_value[4];
					dim_x = int_value[5];
					dim_y = int_value[6];
					depth = int_value[7];

					flash_slot_next = flash_slot_current;

					if(flash_slot_next >= 2)
						flash_slot_next = 0;
				}

				if(option_verbose)
					std::cout <<
							boost::format("flash update available on platform %s, current slot: %u, next slot: %u, "
										"address[0]: 0x%x (sector %u), address[1]: 0x%x (sector %u), "
										"display graphical dimensions: %ux%u px at depth %u") %
										platform % flash_slot_current % flash_slot_next %
										(flash_address[0] * flash_sector_size) % flash_address[0] % (flash_address[1] * flash_sector_size) % flash_address[1] %
										dim_x % dim_y % depth << std::endl;

				if(start == -1)
				{
					if(cmd_ota || cmd_write || cmd_simulate || cmd_verify || cmd_info)
					{
						start = flash_address[flash_slot_next];
						otawrite = true;
					}
					else
						if(!cmd_benchmark && !cmd_image && !cmd_image_epaper && !cmd_read_file && !cmd_write_file)
							throw(hard_exception("start address not set"));
				}

				if(cmd_read)
					this->read(filename, start, length);
				else
					if(cmd_verify)
						this->verify(filename, start);
					else
						if(cmd_ota)
							this->ota(platform, filename, !nocommit, !noreset);
						else
							if(cmd_simulate)
								this->write(platform, filename, start, true, otawrite);
							else
								if(cmd_write)
								{
									this->write(platform, filename, start, false, otawrite);

									if(otawrite && !nocommit)
										this->commit_ota(platform, flash_slot_next, start, !noreset, notemp);
								}
								else
									if(cmd_read_file)
										this->read_file(platform, filename);
									else
										if(cmd_write_file)
											this->write_file(platform, filename);
										else
											if(cmd_benchmark)
												this->benchmark(length);
											else
												if(cmd_image)
													this->image(image_slot, filename, dim_x, dim_y, depth, image_timeout);
												else
													if(cmd_image_epaper)
														this->image_epaper(filename);
			}
		}
	}
	catch(const po::error &e)
	{
		throw((boost::format("e32if: program option exception: %s\n%s") % e.what() % options).str());
	}
	catch(const hard_exception &e)
	{
		throw((boost::format("e32if: error: %s") % e.what()).str());
	}
	catch(const transient_exception &e)
	{
		throw((boost::format("e32if: transient exception: %s") % e.what()).str());
	}
	catch(const e32if_exception &e)
	{
		throw((boost::format("e32if: unknown generic e32if exception: %s") % e.what()).str());
	}
	catch(const std::exception &e)
	{
		throw((boost::format("e32if: standard exception: %s") % e.what()).str());
	}
	catch(const std::string &e)
	{
		throw((boost::format("e32if: unknown standard string exception: %s ") % e).str());
	}
	catch(const char *e)
	{
		throw((boost::format("e32if: unknown string exception: %s") % e).str());
	}
	catch(...)
	{
		throw(std::string("e32if: unknown exception"));
	}
}

static const char *flash_info_expect =
		"OK (flash function|esp32 ota) available, slots: 2, current: ([0-9]), next: ([0-9]), sectors: \\[ ([0-9]+), ([0-9]+) \\], display: ([0-9]+)x([0-9]+)px@([0-9]+)";

enum
{
	sha1_hash_size = 20,
	sha256_hash_size = 32,
};

void E32If::read(const std::string &filename, int sector, int sectors) const
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

		if(config.debug)
			std::cout << boost::format("start read from 0x%x (%u), length 0x%x (%u)") % (sector * config.sector_size) % sector % (sectors * config.sector_size) % sectors << std::endl;

		hash_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(hash_ctx, EVP_sha1(), (ENGINE *)0);

		retries = 0;

		for(current = sector, offset = 0; current < (sector + sectors); current++)
		{
			retries += util->read_sector(config.sector_size, current, data);

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

			std::cout << boost::format("received %3d kbytes in %2.0f seconds at rate %3.0f kbytes/s, received %3u sectors, retries %2u, %3u%%    \r") %
					(offset / 1024) % duration % rate % (current - sector) % retries % ((offset * 100) / (sectors * config.sector_size));
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

	std::cout << boost::format("checksumming %u sectors from %u...") % sectors % sector << std::endl;

	hash_size = sha1_hash_size;
	EVP_DigestFinal_ex(hash_ctx, hash, &hash_size);
	EVP_MD_CTX_free(hash_ctx);

	sha_local_hash_text = Util::hash_to_text(sha1_hash_size, hash);
	util->get_checksum(sector, sectors, sha_remote_hash_text);

	if(sha_local_hash_text != sha_remote_hash_text)
	{
		if(config.verbose)
			std::cout << boost::format("! sector %u / %u, address: 0x%x/0x%x read, checksum failed. Local hash: %s, remote hash: %s") %
					sector % sectors % (sector * config.sector_size) % (sectors * config.sector_size) % sha_local_hash_text % sha_remote_hash_text << std::endl;

		throw(hard_exception("checksum read failed"));
	}

	std::cout << "checksum OK" << std::endl;
}

void E32If::ota(std::string platform, std::string filename, bool commit, bool reset) const
{
	int file_fd, chunk;
	unsigned int offset, length, sectors, attempt, attempts, next_slot, running_slot;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	char sector_buffer[4096];
	struct stat stat;
	std::string partition;
	unsigned int sha256_hash_length;
	unsigned char sha256_hash[sha256_hash_size];
	EVP_MD_CTX *sha256_ctx;
	std::string sha256_local_hash_text;
	std::string sha256_remote_hash_text;

	if(platform != "esp32")
		throw(hard_exception("ota command not supported on esp8266, use write command"));

	if(filename.empty())
		throw(hard_exception("filename required"));

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	try
	{
		fstat(file_fd, &stat);
		length = stat.st_size;
		sectors = (length + (4096 - 1)) / 4096;

		if(length < 32)
			throw(hard_exception("file too short (< 32 bytes)"));

		gettimeofday(&time_start, 0);

		util->process((boost::format("ota-start %u") % length).str(),
				"", reply, nullptr, "OK start write ota partition ([^ ]+) ([0-9]+)", &string_value , &int_value, 5000);
		partition = string_value[0];
		next_slot = int_value[1];

		std::cout << (boost::format("start ota at slot %u (%s), length: %u (%u sectors)\n") %
				next_slot % partition % length % sectors);

		sha256_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), (ENGINE *)0);

		for(offset = 0; offset < length;)
		{
			memset(sector_buffer, 0, sizeof(sector_buffer));

			if(offset == (length - 32))
				chunk = length - offset;
			else
				if((offset + 4096) >= (length - 32))
					chunk = length - 32 - offset;
				else
					chunk = 4096;

			if((chunk = ::read(file_fd, sector_buffer, chunk)) <= 0)
				throw(hard_exception("i/o error in read"));

			offset += chunk;

			if(offset < length)
				EVP_DigestUpdate(sha256_ctx, sector_buffer, chunk);

			command = (boost::format("ota-write %u %u") % chunk % ((offset >= length) ? 1 : 0)).str();

			attempts = 0;

			for(attempt = 4; attempt > 0; attempt--)
			{
				int seconds, useconds;
				double duration;

				gettimeofday(&time_now, 0);

				seconds = time_now.tv_sec - time_start.tv_sec;
				useconds = time_now.tv_usec - time_start.tv_usec;
				duration = seconds + (useconds / 1000000.0);

				std::cout << boost::format("sent %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, attempt %u, %3u%%     \r") %
						(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 4096) % (5 - attempt) % (offset * 100 / length);
				std::cout.flush();

				try
				{
					attempts += process(command, std::string(sector_buffer, chunk), reply, nullptr, "OK write ota");
					break;
				}
				catch(const transient_exception &e)
				{
					if(config.verbose)
						std::cout << std::endl << boost::format("ota sector write failed: %s, reply: %s, retry") % e.what() % reply << std::endl;
					continue;
				}
			}

			if(attempt == 0)
				throw(hard_exception("write ota sector: no more attempts"));
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

	util->process("ota-finish", "", reply, nullptr, "OK finish ota, checksum: ([^ ]+)", &string_value);
	sha256_remote_hash_text = string_value[0];

	sha256_hash_length = sha256_hash_size;
	EVP_DigestFinal_ex(sha256_ctx, sha256_hash, &sha256_hash_length);
	EVP_MD_CTX_free(sha256_ctx);
	sha256_local_hash_text = Util::hash_to_text(sha256_hash_length, sha256_hash);

	if(sha256_local_hash_text != sha256_remote_hash_text)
		throw(hard_exception(boost::format("incorrect checkum, local: %s, remote: %s") % sha256_local_hash_text % sha256_remote_hash_text));

	std::cout << "checksum OK" << std::endl;

	if(!commit)
		return;

	util->process((boost::format("ota-commit %s") % sha256_local_hash_text).str(), "", reply, nullptr, "OK commit ota");

	std::cout << "OTA write finished" << std::endl;

	if(!reset)
		return;

	std::cout << "rebooting " << std::endl;

	try
	{
		util->process("reset", "", reply);
	}
	catch(const transient_exception &e)
	{
		if(config.verbose)
		{
			std::cout << "  reset returned transient error: " << e.what();
			std::cout << std::endl;
		}
	}
	catch(const hard_exception &e)
	{
		if(config.verbose)
		{
			std::cout << "  reset returned error: " << e.what();
			std::cout << std::endl;
		}
	}

	std::cout << "disconnecting " << std::endl;

	channel->disconnect();

	std::cout << "connecting" << std::endl;

	channel->connect(5000);

	std::cout << "connected" << std::endl;

	util->process("flash-info", "", reply, nullptr, flash_info_expect);
	std::cout << "reboot finished" << std::endl;
	util->process("flash-info", "", reply, nullptr, flash_info_expect, &string_value, &int_value);

	if(int_value[1] == 0)
		running_slot = 0;
	else
		running_slot = 1;

	if(next_slot != running_slot)
		throw(hard_exception(boost::format("boot failed, OTA slot: %u, running slot: %u") %
				next_slot % running_slot));

	std::cout << boost::format("boot succeeded, permanently selecting boot slot: %u") % next_slot << std::endl;

	util->process((boost::format("ota-confirm %u") % next_slot).str(), "", reply, nullptr, "OK confirm ota");

	util->process("stats", "", reply, nullptr, "\\s*>\\s*firmware\\s*>\\s*date:\\s*([a-zA-Z0-9: ]+).*", &string_value, &int_value);
	std::cout << boost::format("firmware version: %s") % string_value[0] << std::endl;
}

void E32If::write(std::string platform, std::string filename, int sector, bool simulate, bool otawrite) const
{
	int file_fd, length, current, offset, retries;
	struct timeval time_start, time_now;
	std::string command;
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
	unsigned char sector_buffer[config.sector_size];
	struct stat stat;

	if((platform == "esp32") && otawrite)
		throw(hard_exception("esp32 doesn't support ota over write command, use ota command"));

	if(filename.empty())
		throw(hard_exception("file name required"));

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	fstat(file_fd, &stat);
	length = (stat.st_size + (config.sector_size - 1)) / config.sector_size;

	sectors_skipped = 0;
	sectors_erased = 0;
	sectors_written = 0;
	offset = 0;

	try
	{
		gettimeofday(&time_start, 0);

		if(simulate)
			command = "simulate";
		else
		{
			if(otawrite)
				command = "ota ";
			else
				command = "normal ";

			command += "write";
		}

		std::cout << boost::format("start %s at address 0x%06x (sector %u), length: %u (%u sectors)") %
				command % (sector * config.sector_size) % sector % (length * config.sector_size) % length << std::endl;

		hash_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(hash_ctx, EVP_sha1(), (ENGINE *)0);

		retries = 0;

		for(current = sector; current < (sector + length); current++)
		{
			memset(sector_buffer, 0xff, config.sector_size);

			if((::read(file_fd, sector_buffer, config.sector_size)) <= 0)
				throw(hard_exception("i/o error in read"));

			EVP_DigestUpdate(hash_ctx, sector_buffer, config.sector_size);

			retries += util->write_sector(current, std::string((const char *)sector_buffer, sizeof(sector_buffer)),
					sectors_written, sectors_erased, sectors_skipped, simulate);

			offset += config.sector_size;

			int seconds, useconds;
			double duration, rate;

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);
			rate = offset / 1024.0 / duration;

			std::cout << boost::format("sent %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, written %3u sectors, erased %3u sectors, skipped %3u sectors, retries %2u, %3u%%     \r") %
					(offset / 1024) % duration % rate % (current - sector + 1) % sectors_written % sectors_erased % sectors_skipped % retries %
					(((offset + config.sector_size) * 100) / (length * config.sector_size));
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
		std::cout << boost::format("checksumming %u sectors...") % length << std::endl;

		hash_size = sha1_hash_size;
		EVP_DigestFinal_ex(hash_ctx, hash, &hash_size);
		EVP_MD_CTX_free(hash_ctx);

		sha_local_hash_text = Util::hash_to_text(sha1_hash_size, hash);

		util->get_checksum(sector, length, sha_remote_hash_text);

		if(sha_local_hash_text != sha_remote_hash_text)
			throw(hard_exception(boost::format("checksum failed: SHA hash differs, local: %u, remote: %s") % sha_local_hash_text % sha_remote_hash_text));

		std::cout << "checksum OK" << std::endl;
		std::cout << "write finished" << std::endl;
	}
}

void E32If::verify(const std::string &filename, int sector) const
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
	uint8_t sector_buffer[config.sector_size];
	int retries;

	if(filename.empty())
		throw(hard_exception("file name required"));

	if((file_fd = open(filename.c_str(), O_RDONLY)) < 0)
		throw(hard_exception("can't open file"));

	fstat(file_fd, &stat);
	sectors = (stat.st_size + (config.sector_size - 1)) / config.sector_size;
	offset = 0;

	try
	{
		gettimeofday(&time_start, 0);

		if(config.debug)
			std::cout << boost::format("start verify from 0x%x (%u), length 0x%x (%u)") % (sector * config.sector_size) % sector % (sectors * config.sector_size) % sectors << std::endl;

		retries = 0;

		for(current = sector; current < (sector + sectors); current++)
		{
			memset(sector_buffer, 0xff, config.sector_size);

			if(::read(file_fd, sector_buffer, sizeof(sector_buffer)) <= 0)
				throw(hard_exception("i/o error in read"));

			local_data.assign((const char *)sector_buffer, sizeof(sector_buffer));

			retries += util->read_sector(config.sector_size, current, remote_data);

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

			std::cout << boost::format("received %3u kbytes in %2.0f seconds at rate %3.0f kbytes/s, received %3u sectors, retries %2u, %3u%%     \r") %
					(offset / 1024) % duration % rate % (current - sector) % retries % ((offset * 100) / (sectors * config.sector_size));
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

void E32If::benchmark(int length) const
{
	unsigned int phase, retries, iterations, current;
	std::string command;
	std::string data(config.sector_size, '\0');
	std::string expect;
	std::string reply;
	struct timeval time_start, time_now;
	int seconds, useconds;
	double duration, rate;

	iterations = length;

	for(phase = 0; phase < 2; phase++)
	{
		retries = 0;

		gettimeofday(&time_start, 0);

		for(current = 0; current < iterations; current++)
		{
			if(phase == 0)
				retries += util->process("flash-bench 0",
						data,
						reply,
						nullptr,
						"OK flash-bench: sending 0 bytes");
			else
				retries += util->process((boost::format("flash-bench %u") % config.sector_size).str(),
						"",
						reply,
						&data,
						(boost::format("OK flash-bench: sending %u bytes") % config.sector_size).str().c_str());

			if(!config.debug)
			{
				gettimeofday(&time_now, 0);

				seconds = time_now.tv_sec - time_start.tv_sec;
				useconds = time_now.tv_usec - time_start.tv_usec;
				duration = seconds + (useconds / 1000000.0);
				rate = current * 4.0 / duration;

				std::cout << boost::format("%s %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %4u sectors, retries %2u, %3u%%     \r") %
						((phase == 0) ? "sent     " : "received ") % (current * config.sector_size / 1024) % duration % rate % (current + 1) % retries % (((current + 1) * 100) / iterations);
				std::cout.flush();
			}
		}

		usleep(200000);
		std::cout << std::endl;
	}
}

void E32If::image_send_sector(int current_sector, const std::string &data,
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
		util->process(command, data, reply, nullptr, "display plot success: yes");
	}
	else
	{
		unsigned int sectors_written, sectors_erased, sectors_skipped;
		std::string pad;
		unsigned int pad_length = 4096 - data.length();

		pad.assign(pad_length, 0x00);

		util->write_sector(current_sector, data + pad, sectors_written, sectors_erased, sectors_skipped, false);
	}
}

void E32If::image(int image_slot, const std::string &filename,
		unsigned int dim_x, unsigned int dim_y, unsigned int depth, int image_timeout) const
{
	struct timeval time_start, time_now;
	int current_sector;

	gettimeofday(&time_start, 0);

	if(image_slot == 0)
		current_sector = 0x200000 / config.sector_size;
	else
		if(image_slot == 1)
			current_sector = 0x280000 / config.sector_size;
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
		unsigned char sector_buffer[config.sector_size];
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

		if(config.debug)
			std::cout << boost::format("image loaded from %s, %ux%u, version %s") % filename % image.columns() % image.rows() % image.magick() << std::endl;

		image.filterType(Magick::TriangleFilter);
		image.resize(newsize);

		if((image.columns() != dim_x) || (image.rows() != dim_y))
			throw(hard_exception("image magic resize failed"));

		image.modifyImage();

		pixel_cache = image.getPixels(0, 0, dim_x, dim_y);

		if(image_slot < 0)
			util->process((boost::format("display-freeze %u") % 10000).str(), "", reply, nullptr,
					"display freeze success: yes");

		current_buffer = 0;
		start_x = 0;
		start_y = 0;

		memset(sector_buffer, 0xff, config.sector_size);

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
						if((current_buffer / 8) + 1 > config.sector_size)
						{
							image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer / 8), start_x, start_y, depth);
							memset(sector_buffer, 0xff, config.sector_size);
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

						if((current_buffer + 2) > config.sector_size)
						{
							image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer), start_x, start_y, depth);
							memset(sector_buffer, 0xff, config.sector_size);

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
						if((current_buffer + 3) > config.sector_size)
						{
							image_send_sector(current_sector, std::string((const char *)sector_buffer, current_buffer), start_x, start_y, depth);
							memset(sector_buffer, 0xff, config.sector_size);

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

			std::cout << boost::format("sent %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, x %3u, y %3u, %3u%%    \r") %
					((x * 2 * y) / 1024) % duration % rate % x % y % ((x * y * 100) / (dim_x * dim_y));
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
			util->process((boost::format("display-freeze %u") % 0).str(), "", reply, nullptr,
					"display freeze success: yes");

		if((image_slot < 0) && (image_timeout > 0))
			util->process((boost::format("display-freeze %u") % image_timeout).str(), "", reply, nullptr,
					"display freeze success: yes");
	}
	catch(const Magick::Error &error)
	{
		throw(hard_exception(boost::format("image: load failed: %s") % error.what()));
	}
	catch(const Magick::Warning &warning)
	{
		std::cout << boost::format("image: %s") % warning.what() << std::endl;
	}
}

void E32If::cie_spi_write(const std::string &data, const char *match) const
{
	std::string reply;

	util->process(data, "", reply, nullptr, match);
}

void E32If::cie_uc_cmd_data(bool isdata, unsigned int data_value) const
{
	boost::format fmt("spt 17 8 %02x 0 0 0 0");
	std::string reply;

	fmt % data_value;

	cie_spi_write("sps", "spi start ok");
	cie_spi_write(std::string("iw 1 0 ") + (isdata ? "1" : "0"), (std::string("digital output: \\[") + (isdata ? "1" : "0") + "\\]").c_str());
	cie_spi_write(fmt.str(), "spi transmit ok");
	cie_spi_write("spf", "spi finish ok");
}

void E32If::cie_uc_cmd(unsigned int cmd) const
{
	return(cie_uc_cmd_data(false, cmd));
}

void E32If::cie_uc_data(unsigned int data) const
{
	return(cie_uc_cmd_data(true, data));
}

void E32If::cie_uc_data_string(const std::string valuestring) const
{
	cie_spi_write("iw 1 0 1", "digital output: \\[1\\]");
	cie_spi_write("sps", "spi start ok");
	cie_spi_write((boost::format("spw 8 %s") % valuestring).str(), "spi write ok");
	cie_spi_write("spt 17 0 0 0 0 0 0 0", "spi transmit ok");
	cie_spi_write("spf", "spi finish ok");
}

void E32If::image_epaper(const std::string &filename) const
{
	static const unsigned int dim_x = 212;
	static const unsigned int dim_y = 104;
	uint8_t dummy_display[dim_x][dim_y];
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	std::string values, command, reply;
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

		if(config.debug)
			std::cout << boost::format("image loaded from %s, %ux%u, version: %s") % filename % image.columns() % image.rows() % image.magick() << std::endl;

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
						values.append((boost::format("%02x ") % byte).str());
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

				std::cout << boost::format("sent %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, x %3u, y %3u, %3u%%     \r") %
						(all_bytes / 1024) % duration % rate % x % y % (((dim_x - 1 - x) * y * 100) / (2 * dim_x * dim_y));
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
	catch(const Magick::Error &e)
	{
		throw(hard_exception(boost::format("image epaper: load failed: %s") % e.what()));
	}
	catch(const Magick::Warning &e)
	{
		std::cout << boost::format("image epaper: %s") % e.what() << std::endl;
	}

	if(config.debug)
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

std::string E32If::send(std::string args) const
{
	std::string arg;
	size_t current;
	Packet send_packet;
	std::string send_data;
	Packet receive_packet;
	std::string receive_data;
	std::string reply;
	std::string reply_oob;
	std::string output;
	int retries;

	if(config.dontwait)
	{
		if(daemon(0, 0))
		{
			perror("daemon");
			return(std::string(""));
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

		retries = util->process(arg, "", reply, &reply_oob);

		output.append(reply);

		if(reply_oob.length() > 0)
		{
			unsigned int length = 0;

			output.append((boost::format("\n%u bytes of OOB data: ") % reply_oob.length()).str());

			for(const auto &it : reply_oob)
			{
				if((length++ % 20) == 0)
					output.append("\n    ");

				output.append((boost::format("0x%02x ") % (((unsigned int)it) & 0xff)).str());
			}

		}

		output.append("\n");

		if((retries > 0) && config.verbose)
			std::cout << boost::format("%u retries\n") % retries;
	}

	return(output);
}

std::string E32If::multicast(const std::string &args)
{
	Packet send_packet(args);
	Packet receive_packet;
	std::string send_data;
	std::string receive_data;
	std::string reply_data;
	std::string packet;
	struct timeval tv_start, tv_now;
	uint64_t start, now;
	uint32_t hostid;
	std::string hostname;
	std::string reply;
	std::string info;
	std::string line;
	typedef struct { int count; std::string hostname; std::string text; } multicast_reply_t;
	typedef std::map<unsigned uint32_t, multicast_reply_t> multicast_replies_t;
	multicast_replies_t multicast_replies;
	int total_replies, total_hosts;
	int run;
	uint32_t transaction_id;
	std::string output;
	bool complete;

	transaction_id = prn();
	packet = send_packet.encapsulate(config.raw, config.provide_checksum, config.request_checksum, config.broadcast_group_mask, &transaction_id);

	if(config.dontwait)
	{
		for(run = 0; run < (int)config.multicast_burst; run++)
		{
			send_data = packet;
			channel->send(send_data);
			usleep(100000);
		}

		return(std::string(""));
	}

	total_replies = total_hosts = 0;

	gettimeofday(&tv_start, nullptr);
	start = (tv_start.tv_sec * 1000000) + tv_start.tv_usec;

	for(run = 0; run < (int)config.multicast_burst; run++)
	{
		gettimeofday(&tv_now, nullptr);
		now = (tv_now.tv_sec * 1000000) + tv_now.tv_usec;

		if(((now - start) / 1000ULL) > 10000)
			break;

		send_data = packet;
		channel->send(send_data);

		for(complete = false; !complete;)
		{
			reply_data.clear();
			complete = channel->receive(reply_data, -1, &hostid, &hostname);
			receive_packet.clear();
			receive_packet.append_data(reply_data);

			if(!receive_packet.decapsulate(&reply_data, nullptr, config.verbose, nullptr, &transaction_id))
			{
				if(config.verbose)
					std::cout << "multicast: cannot decapsulate" << std::endl;

				continue;
			}

			total_replies++;

			auto it = multicast_replies.find(hostid);

			if(it != multicast_replies.end())
				it->second.count++;
			else
			{
				total_hosts++;
				multicast_reply_t entry;

				entry.count = 1;
				entry.hostname = hostname;
				entry.text = reply_data;
				multicast_replies[hostid] = entry;
			}
		}
	}

	for(auto &it : multicast_replies)
	{
		boost::format ip("%u.%u.%u.%u");

		ip % ((it.first & 0xff000000) >> 24) %
				((it.first & 0x00ff0000) >> 16) %
				((it.first & 0x0000ff00) >>  8) %
				((it.first & 0x000000ff) >>  0);

		output.append((boost::format("%-14s %2u %-12s %s\n") % ip % it.second.count % it.second.hostname % it.second.text).str());
	}

	output.append((boost::format("\n%u probes sent, %u replies received, %u hosts\n") % config.multicast_burst % total_replies % total_hosts).str());

	return(output);
}

void E32If::commit_ota(std::string platform, unsigned int flash_slot, unsigned int sector, bool reset, bool notemp)
{
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	std::string send_data;
	Packet packet;
	static const char *flash_select_expect = "OK flash-select: slot ([0-9]+) selected, sector ([0-9]+), permanent ([0-1])";

	if(platform == "esp32")
		return;

	send_data = (boost::format("flash-select %u %u") % flash_slot % (notemp ? 1 : 0)).str();
	util->process(send_data, "", reply, nullptr, flash_select_expect, &string_value, &int_value);

	if(int_value[0] != (int)flash_slot)
		throw(hard_exception(boost::format("flash-select failed, local slot (%u) != remote slot (%u)") % flash_slot % int_value[0]));

	if(int_value[1] != (int)sector)
		throw(hard_exception("flash-select failed, local sector != remote sector"));

	if(int_value[2] != notemp ? 1 : 0)
		throw(hard_exception("flash-select failed, local permanent != remote permanent"));

	std::cout << boost::format("selected %s boot slot: %u") % (notemp ? "permanent" : "one time") % flash_slot << std::endl;

	if(!reset)
		return;

	std::cout << "rebooting... ";
	std::cout.flush();

	packet.clear();
	packet.append_data("reset\n");
	send_data = packet.encapsulate(config.raw, config.provide_checksum, config.request_checksum, config.broadcast_group_mask);
	channel->send(send_data);
	channel->disconnect();
	channel->connect();
	util->process("flash-info", "", reply, nullptr, flash_info_expect, &string_value, &int_value);
	std::cout << "reboot finished" << std::endl;
	util->process("flash-info", "", reply, nullptr, flash_info_expect, &string_value, &int_value);

	if(int_value[1] != (int)flash_slot)
		throw(hard_exception(boost::format("boot failed, requested slot (%u) != active slot (%u)") % flash_slot % int_value[1]));

	if(!notemp)
	{
		std::cout << boost::format("boot succeeded, permanently selecting boot slot: %u") % flash_slot << std::endl;

		send_data = (boost::format("flash-select %u 1") % flash_slot).str();
		util->process(send_data, "", reply, nullptr, flash_select_expect, &string_value, &int_value);

		if(int_value[0] != (int)flash_slot)
			throw(hard_exception(boost::format("flash-select failed, local slot (%u) != remote slot (%u)") % flash_slot % int_value[0]));

		if(int_value[1] != (int)sector)
			throw(hard_exception("flash-select failed, local sector != remote sector"));

		if(int_value[2] != 1)
			throw(hard_exception("flash-select failed, local permanent != remote permanent"));
	}

	util->process("stats", "", reply, nullptr, "\\s*>\\s*firmware\\s*>\\s*date:\\s*([a-zA-Z0-9: ]+).*", &string_value, &int_value);
	std::cout << boost::format("firmware version: %s") % string_value[0] << std::endl;
}

int E32If::process(const std::string &data, const std::string &oob_data,
				std::string &reply_data, std::string *reply_oob_data,
				const char *match, std::vector<std::string> *string_value, std::vector<int> *int_value) const
{
	return(util->process(data, oob_data, reply_data, reply_oob_data, match, string_value, int_value));
}

void E32If::read_file(std::string platform, std::string filename)
{
	int file_fd, chunk;
	unsigned int offset, attempt, attempts;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::string oob;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	std::string partition;
	EVP_MD_CTX *sha256_ctx;
	unsigned char sha256_hash[sha256_hash_size];
	unsigned int sha256_hash_length;
	std::string sha256_local_hash_text;
	std::string sha256_remote_hash_text;
	unsigned int pos;

	if(platform != "esp32")
		throw(hard_exception("read file only supported on esp32"));

	if(filename.empty())
		throw(hard_exception("filename required"));

	if((file_fd = open(filename.c_str(), O_WRONLY | O_CREAT, 0666)) < 0)
		throw(hard_exception("file not found"));

	try
	{
		if((pos = filename.find_last_of('/')) != std::string::npos)
			filename = filename.substr(pos + 1);

		gettimeofday(&time_start, 0);

		sha256_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), (ENGINE *)0);

		for(offset = 0;;)
		{
			command = (boost::format("fs-read %u %s %s") % 4096 % offset % filename).str();

			attempts = 0;

			for(attempt = 4; attempt > 0; attempt--)
			{
				if(!config.debug)
				{
					int seconds, useconds;
					double duration;

					gettimeofday(&time_now, 0);

					seconds = time_now.tv_sec - time_start.tv_sec;
					useconds = time_now.tv_usec - time_start.tv_usec;
					duration = seconds + (useconds / 1000000.0);

					std::cout << boost::format("received %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, attempt %u      \r") %
							(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 4096) % (5 - attempt);
					std::cout.flush();
				}

				try
				{
					oob.clear();
					attempts += process(command, "", reply, &oob, "OK chunk read: ([0-9]+)", nullptr, &int_value);
					chunk = int_value[0];

					if((unsigned int)chunk != oob.length())
						throw(hard_exception(boost::format("chunk size [%u] differs from oob size [%u]") % chunk % oob.length()));

					break;
				}
				catch(const transient_exception &e)
				{
					if(config.verbose)
						std::cout << std::endl << boost::format("write file failed: %s, reply: %s, retry") % e.what() % reply << std::endl;
					continue;
				}
			}

			if(attempt == 0)
				throw(hard_exception("write file: no more attempts"));

			if(chunk == 0)
				break;

			if((chunk = ::write(file_fd, oob.data(), oob.length())) != (int)oob.length())
				throw(hard_exception("i/o error in write"));

			offset += chunk;

			EVP_DigestUpdate(sha256_ctx, oob.data(), oob.length());
		}
	}
	catch(...)
	{
		std::cout << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	sha256_hash_length = sha256_hash_size;
	EVP_DigestFinal_ex(sha256_ctx, sha256_hash, &sha256_hash_length);
	EVP_MD_CTX_free(sha256_ctx);
	sha256_local_hash_text = Util::hash_to_text(sha256_hash_size, sha256_hash);

	process(std::string("fs-checksum ") + filename, "", reply, nullptr, "OK checksum: ([0-9a-f]+)", &string_value, &int_value);

	sha256_remote_hash_text = string_value[0];

	if(sha256_local_hash_text != sha256_remote_hash_text)
		throw(hard_exception(boost::format("checksum failed: SHA256 hash differs, local: %u, remote: %s") % sha256_local_hash_text % sha256_remote_hash_text));

	std::cout << std::endl;
}

void E32If::write_file(std::string platform, std::string filename)
{
	int file_fd, chunk;
	unsigned int offset, length, attempt, attempts;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	char buffer[4096];
	struct stat stat;
	std::string partition;
	EVP_MD_CTX *sha256_ctx;
	unsigned char sha256_hash[sha256_hash_size];
	unsigned int sha256_hash_length;
	std::string sha256_local_hash_text;
	std::string sha256_remote_hash_text;
	unsigned int pos;

	if(platform != "esp32")
		throw(hard_exception("write file only supported on esp32"));

	if(filename.empty())
		throw(hard_exception("filename required"));

	if((pos = filename.find_last_of('/')) != std::string::npos)
		filename = filename.substr(pos + 1);

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	try
	{
		process(std::string("fs-erase ") + filename, "", reply, nullptr, "OK file erased");

		fstat(file_fd, &stat);
		length = stat.st_size;
		gettimeofday(&time_start, 0);

		sha256_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), (ENGINE *)0);

		for(offset = 0; offset < length;)
		{
			if((chunk = ::read(file_fd, buffer, sizeof(buffer))) <= 0)
				throw(hard_exception("i/o error in read"));

			offset += chunk;

			EVP_DigestUpdate(sha256_ctx, buffer, chunk);

			command = (boost::format("fs-append %u %s") % chunk % filename).str();

			attempts = 0;

			for(attempt = 4; attempt > 0; attempt--)
			{
				if(!config.debug)
				{
					int seconds, useconds;
					double duration;

					gettimeofday(&time_now, 0);

					seconds = time_now.tv_sec - time_start.tv_sec;
					useconds = time_now.tv_usec - time_start.tv_usec;
					duration = seconds + (useconds / 1000000.0);

					std::cout << boost::format("sent %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, attempt %u, %3u%%     \r") %
							(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 4096) % (5 - attempt) % (offset * 100 / length);
					std::cout.flush();
				}

				try
				{
					attempts += process(command, std::string(buffer, chunk), reply, nullptr, "OK file length: ([0-9]+)", &string_value, &int_value);

					if(int_value[0] != (int)offset)
						throw(hard_exception(boost::format("write file: remote file length [%u] != local offset [%u]") % int_value[0] % offset));

					break;
				}
				catch(const transient_exception &e)
				{
					if(config.verbose)
						std::cout << std::endl << boost::format("write file failed: %s, reply: %s, retry") % e.what() % reply << std::endl;
					continue;
				}
			}

			if(attempt == 0)
				throw(hard_exception("write file: no more attempts"));
		}
	}
	catch(...)
	{
		std::cout << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	sha256_hash_length = sha256_hash_size;
	EVP_DigestFinal_ex(sha256_ctx, sha256_hash, &sha256_hash_length);
	EVP_MD_CTX_free(sha256_ctx);
	sha256_local_hash_text = Util::hash_to_text(sha256_hash_size, sha256_hash);

	process(std::string("fs-checksum ") + filename, "", reply, nullptr, "OK checksum: ([0-9a-f]+)", &string_value, &int_value);

	sha256_remote_hash_text = string_value[0];

	if(sha256_local_hash_text != sha256_remote_hash_text)
		throw(hard_exception(boost::format("checksum failed: SHA256 hash differs, local: %u, remote: %s") % sha256_local_hash_text % sha256_remote_hash_text));

	std::cout << std::endl;
}
