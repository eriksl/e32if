#include "e32if.h"
#include "exception.h"
#include "packet.h"
#include "udp_socket.h"
#include "tcp_socket.h"
#include "bt_socket.h"
#include "util.h"

#include <string>
#include <vector>
#include <iostream>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include <boost/program_options.hpp>

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/evp.h>
#include <Magick++.h>

namespace po = boost::program_options;

enum
{
	max_chunk_size = 4096,
};

typedef enum
{
	transport_none = 0,
	transport_tcp_ip = 1,
	transport_udp_ip = 2,
	transport_bluetooth = 3,
} transport_t;

static const char *info_board_match_string = "firmware date: ([A-Za-z0-9: ]+), transport mtu: ([0-9]+), display area: ([0-9]+)x([0-9]+)";

E32If::E32If()
{
	channel = nullptr;
	raw = false;
	verbose = false;
	debug = false;
}

E32If::~E32If()
{
	if(channel)
	{
		delete channel;
		channel = nullptr;
	}
}

int E32If::process(const std::string &data, const std::string &oob_data, std::string &reply_data, std::string *reply_oob_data_in,
		const char *match, std::vector<std::string> *string_value, std::vector<int> *int_value, int timeout) const
{
	enum { max_attempts = 2 };
	unsigned int attempt;
	std::string packet;
	std::string receive_data;
	std::string reply_oob_data;
	boost::smatch capture;
	boost::regex re(match ? match : "");
	unsigned int captures;
	bool packetised;
	Packet packet_engine(!raw, verbose, debug);

	if(debug)
		std::cerr << Util::dumper("process: send data", data) << std::endl;

	if(data.length() > max_chunk_size)
		throw(hard_exception("process: data size too large"));

	if(oob_data.length() > max_chunk_size)
		throw(hard_exception("process: oob data size too large"));

	packet = packet_engine.encapsulate(data, oob_data);

	for(attempt = 0; attempt < max_attempts; attempt++)
	{
		try
		{
			channel->send(packet, timeout);
			channel->receive(receive_data, timeout);

			if(debug)
				std::cerr << Util::dumper("process: receive data", receive_data) << std::endl;

			if(!packet_engine.decapsulate(receive_data, reply_data, reply_oob_data, packetised))
				throw(transient_exception("decapsulation failed"));

			if(reply_oob_data_in)
				*reply_oob_data_in = reply_oob_data;

			if(match && !boost::regex_match(reply_data, capture, re))
				throw(transient_exception(boost::format("received string does not match: \"%s\" vs. \"%s\"") % Util::dumper("reply", reply_data) % match));

			break;
		}
		catch(const transient_exception &e)
		{
			if(debug || verbose)
				std::cerr << boost::format("process attempt #%u failed: %s, backoff %u ms") % attempt % e.what() % timeout << std::endl;

			channel->drain(timeout);

			continue;
		}
	}

	if(verbose && (attempt > 0))
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

	if(debug)
	{
		std::cerr << Util::dumper("process: reply data", reply_data) << std::endl;

		if(reply_oob_data.length())
			std::cerr << reply_oob_data.length () << " bytes OOB data received" << std::endl;
	}

	return(attempt);
}

std::string E32If::get()
{
	std::string rv = output;
	output.clear();

	return(rv);
}

void E32If::run(const std::vector<std::string> &args)
{
	_run(args);
}

void E32If::run(int argc, const char * const *argv)
{
	int ix;
	std::vector<std::string> args;

	for(ix = 1; ix < argc; ix++)
		args.push_back(std::string(argv[ix]));

	_run(args);
}

void E32If::run(const std::string &args)
{
	std::vector<std::string> args_split;

	args_split = po::split_unix(args);

	_run(args_split);
}

void E32If::_run(const std::vector<std::string> &argv)
{
	po::options_description	options("e32if usage");

	try
	{
		bool option_raw = false;
		bool option_noprobe = false;
		bool option_verbose = false;
		bool option_debug = false;
		std::vector<std::string> host_args;
		std::string host;
		std::string args;
		std::string command_port;
		std::string filename;
		std::string directory;
		std::string start_string;
		std::string transport;
		unsigned int timeout = 0;
		std::string page_id;
		std::string page_text;
		bool cmd_ota = false;
		bool cmd_text = false;
		bool cmd_image = false;
		bool cmd_write_file = false;
		bool cmd_read_file = false;
		bool cmd_perf_test_write = false;
		bool cmd_perf_test_read = false;
		unsigned int selected;
		transport_t transport_type;
		unsigned int x_size, y_size;

		transport = "udp";

		options.add_options()
			("text",			po::bool_switch(&cmd_text)->implicit_value(true),				"add text page")
			("image",			po::bool_switch(&cmd_image)->implicit_value(true),				"add image page")
			("ota",				po::bool_switch(&cmd_ota)->implicit_value(true),				"OTA write")
			("write-file",		po::bool_switch(&cmd_write_file)->implicit_value(true),			"WRITE FILE")
			("read-file",		po::bool_switch(&cmd_read_file)->implicit_value(true),			"READ FILE")
			("host",			po::value<std::vector<std::string> >(&host_args)->required(),	"host use")
			("verbose",			po::bool_switch(&option_verbose)->implicit_value(true),			"verbose output")
			("debug",			po::bool_switch(&option_debug)->implicit_value(true),			"packet trace etc.")
			("transport",		po::value<std::string>(&transport),								"select transport: udp (default), tcp or bluetooth (bt)")
			("page-id",			po::value<std::string>(&page_id),								"name of info page")
			("page-text",		po::value<std::string>(&page_text),								"contents of text page")
			("timeout",			po::value<unsigned int>(&timeout),								"timeout of text page in seconds")
			("filename",		po::value<std::string>(&filename),								"file")
			("directory",		po::value<std::string>(&directory),								"destination directory")
			("command-port",	po::value<std::string>(&command_port)->default_value("24"),		"command port to connect to")
			("raw",				po::bool_switch(&option_raw)->implicit_value(true),				"do not use packet encapsulation")
			("noprobe",			po::bool_switch(&option_noprobe)->implicit_value(true),			"skip probe for board information (mtu)")
			("pw",				po::bool_switch(&cmd_perf_test_write)->implicit_value(true),	"performance test WRITE")
			("pr",				po::bool_switch(&cmd_perf_test_read)->implicit_value(true),		"performance test READ");

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

		selected = 0;

		if(cmd_text)
			selected++;

		if(cmd_image)
			selected++;

		if(cmd_ota)
			selected++;

		if(cmd_read_file)
			selected++;

		if(cmd_write_file)
			selected++;

		if(cmd_perf_test_read)
		{
			command_port = "19"; // chargen
			selected++;
		}

		if(cmd_perf_test_write)
		{
			command_port = "9"; // discard
			selected++;
		}

		if(selected > 1)
			throw(hard_exception("specify one command"));

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

		raw = option_raw;
		verbose = option_verbose;
		debug = option_debug;

		struct timeval tv;
		gettimeofday(&tv, nullptr);

		if(channel)
		{
			delete channel;
			channel = nullptr;
		}

		switch(transport_type)
		{
			case(transport_tcp_ip):
			{
				channel = new TCPSocket(option_verbose, option_debug);
				break;
			}

			case(transport_udp_ip):
			{
				channel = new UDPSocket(option_verbose, option_debug);
				break;
			}

			case(transport_bluetooth):
			{
				channel = new BTSocket(option_verbose, option_debug);
				break;
			}

			default:
			{
				throw(hard_exception("e32if: unknown transport"));
			}
		}

		channel->connect(host, command_port);

		if(!option_noprobe)
		{
			std::string reply;
			std::vector<int> int_value;
			std::vector<std::string> string_value;

			try
			{
				process("info-board", "", reply, nullptr, info_board_match_string, &string_value, &int_value);
			}
			catch(const e32if_exception &e)
			{
				throw(hard_exception(boost::format("incompatible image: %s") % e.what()));
			}

			channel->mtu(int_value[1]);
			x_size = int_value[2];
			y_size = int_value[3];

			if(verbose)
			{
				std::cout << "mtu: " << int_value[1] << std::endl;
				std::cout << "display dimensions: " << x_size << "x" << y_size << std::endl;
			}
		}
		else
		{
			x_size = 0;
			y_size = 0;
		}

		if(selected == 0)
			output = this->send_text(args);
		else
			if(cmd_perf_test_write)
				output = this->perf_test_write();
			else
				if(cmd_perf_test_read)
					output = this->perf_test_read();
				else
					if(cmd_text)
						this->text(page_id, timeout, page_text);
					else
						if(cmd_image)
							this->image(page_id, timeout, directory, filename, x_size, y_size);
						else
							if(cmd_ota)
								this->ota(filename);
							else
								if(cmd_read_file)
									this->read_file(directory, filename);
								else
									if(cmd_write_file)
										this->write_file(directory, filename);
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

enum
{
	sha256_hash_size = 32,
};

void E32If::ota(std::string filename) const
{
	int file_fd, chunk_size;
	unsigned int offset, attempt, attempts, length;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	char sector_buffer[max_chunk_size];
	struct stat stat;
	unsigned int sha256_hash_length;
	unsigned char sha256_hash[sha256_hash_size];
	EVP_MD_CTX *sha256_ctx;
	std::string sha256_local_hash_text;
	std::string sha256_remote_hash_text;

	if(filename.empty())
		throw(hard_exception("filename required"));

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	try
	{
		fstat(file_fd, &stat);
		length = stat.st_size;

		if(length < 32)
			throw(hard_exception("file too short (< 32 bytes)"));

		gettimeofday(&time_start, 0);

		process((boost::format("ota-start %u") % length).str(), "", reply, nullptr, "OK start write ota to partition ([0-9]+)/([a-zA-Z0-9_ -]+)", &string_value, &int_value , 5000);

		std::cerr << (boost::format("start ota to [%u]: \"%s\", length: %u (%u sectors)\n") % int_value[0] % string_value[1] % length % ((length + (4096 - 1)) / 4096));

		sha256_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), (ENGINE *)0);

		for(offset = 0; offset < length;)
		{
			memset(sector_buffer, 0, sizeof(sector_buffer));

			if(offset == (length - 32))
				chunk_size = length - offset;
			else
				if((offset + max_chunk_size) >= (length - 32))
					chunk_size = length - 32 - offset;
				else
					chunk_size = max_chunk_size;

			if((chunk_size = ::read(file_fd, sector_buffer, chunk_size)) <= 0)
				throw(hard_exception("i/o error in read"));

			offset += chunk_size;

			if(offset < length)
				EVP_DigestUpdate(sha256_ctx, sector_buffer, chunk_size);

			command = (boost::format("ota-write %u %u") % chunk_size % ((offset >= length) ? 1 : 0)).str();

			attempts = 0;

			for(attempt = 4; attempt > 0; attempt--)
			{
				int seconds, useconds;
				double duration;

				gettimeofday(&time_now, 0);

				seconds = time_now.tv_sec - time_start.tv_sec;
				useconds = time_now.tv_usec - time_start.tv_usec;
				duration = seconds + (useconds / 1000000.0);

				std::cerr << boost::format("sent %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, attempt %u, %3u%%     \r") %
						(offset / 1024) %
						duration %
						(offset / 1024 / duration) %
						(offset / 4096) %
						(5 - attempt) %
						(offset * 100 / length);
				std::cerr.flush();

				try
				{
					attempts += process(command, std::string(sector_buffer, chunk_size), reply, nullptr, "OK write ota");
					break;
				}
				catch(const transient_exception &e)
				{
					if(verbose)
						std::cerr << std::endl << boost::format("ota sector write failed: %s, reply: %s, retry") % e.what() % reply << std::endl;
					continue;
				}
			}

			if(attempt == 0)
				throw(hard_exception("write ota sector: no more attempts"));
		}
	}
	catch(...)
	{
		std::cerr << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	std::cerr << std::endl;

	process("ota-finish", "", reply, nullptr, "OK finish ota, checksum: ([^ ]+)", &string_value);
	sha256_remote_hash_text = string_value[0];

	sha256_hash_length = sha256_hash_size;
	EVP_DigestFinal_ex(sha256_ctx, sha256_hash, &sha256_hash_length);
	EVP_MD_CTX_free(sha256_ctx);
	sha256_local_hash_text = Util::hash_to_text(sha256_hash_length, sha256_hash);

	if(sha256_local_hash_text != sha256_remote_hash_text)
		throw(hard_exception(boost::format("incorrect checkum, local: %s, remote: %s") % sha256_local_hash_text % sha256_remote_hash_text));

	std::cerr << "checksum OK" << std::endl;

	process((boost::format("ota-commit %s") % sha256_local_hash_text).str(), "", reply, nullptr, "OK commit ota");

	std::cerr << "OTA write finished, rebooting" << std::endl;

	try
	{
		process("reset", "", reply, nullptr, nullptr, nullptr, nullptr, 2000);
	}
	catch(const transient_exception &e)
	{
		if(verbose)
		{
			std::cerr << "  reset returned transient error: " << e.what();
			std::cerr << std::endl;
		}
	}
	catch(const hard_exception &e)
	{
		if(verbose)
		{
			std::cerr << "  reset returned error: " << e.what();
			std::cerr << std::endl;
		}
	}

	std::cerr << "reconnecting " << std::endl;
	channel->reconnect(25000);
	std::cerr << "connected" << std::endl;

	process("info-board", "", reply, nullptr, info_board_match_string, &string_value, &int_value, 100);
	std::cerr << "reboot finished, confirming boot slot" << std::endl;

	process("ota-confirm", "", reply, nullptr, "OK confirm ota");

	std::cerr << boost::format("firmware version: %s") % string_value[0] << std::endl;
}

std::string E32If::send_text(std::string arg) const
{
	std::string send_data;
	std::string receive_data;
	std::string reply;
	std::string reply_oob;
	std::string local_output;
	int retries;

	retries = process(arg, "", reply, &reply_oob);

	local_output.append(reply);

	if(reply_oob.length() > 0)
	{
		unsigned int length = 0;

		local_output.append((boost::format("\n%u bytes of OOB data: ") % reply_oob.length()).str());

		for(const auto &it : reply_oob)
		{
			if((length++ % 20) == 0)
				local_output.append("\n    ");

			local_output.append((boost::format("0x%02x ") % (((unsigned int)it) & 0xff)).str());
		}
	}

	local_output.append("\n");

	if((retries > 0) && verbose)
		std::cerr << boost::format("%u retries\n") % retries;

	return(local_output);
}

void E32If::read_file(std::string directory, std::string filename)
{
	int file_fd, chunk_size;
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
	std::string local_filename;

	if(filename.empty())
		throw(hard_exception("filename required"));

	if(directory.empty())
		directory = ".";

	if((pos = filename.find_last_of('/')) != std::string::npos)
		local_filename = directory + "/" + filename.substr(pos + 1);

	if((file_fd = open(local_filename.c_str(), O_WRONLY | O_CREAT, 0666)) < 0)
		throw(hard_exception("file not found"));

	try
	{
		gettimeofday(&time_start, 0);

		sha256_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), (ENGINE *)0);

		for(offset = 0;;)
		{
			command = (boost::format("fs-read %u %s %s") % 4096 % offset % filename).str();

			attempts = 0;

			for(attempt = 4; attempt > 0; attempt--)
			{
				if(!debug)
				{
					int seconds, useconds;
					double duration;

					gettimeofday(&time_now, 0);

					seconds = time_now.tv_sec - time_start.tv_sec;
					useconds = time_now.tv_usec - time_start.tv_usec;
					duration = seconds + (useconds / 1000000.0);

					std::cerr << boost::format("received %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, attempt %u      \r") %
							(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 4096) % (5 - attempt);
					std::cerr.flush();
				}

				try
				{
					oob.clear();
					attempts += process(command, "", reply, &oob, "OK chunk read: ([0-9]+)", nullptr, &int_value);
					chunk_size = int_value[0];

					if((unsigned int)chunk_size != oob.length())
						throw(hard_exception(boost::format("chunk size [%u] differs from oob size [%u]") % chunk_size % oob.length()));

					break;
				}
				catch(const transient_exception &e)
				{
					if(verbose)
						std::cerr << std::endl << boost::format("write file failed: %s, reply: %s, retry") % e.what() % reply << std::endl;
					continue;
				}
			}

			if(attempt == 0)
				throw(hard_exception("write file: no more attempts"));

			if(chunk_size == 0)
				break;

			if((chunk_size = ::write(file_fd, oob.data(), oob.length())) != (int)oob.length())
				throw(hard_exception("i/o error in write"));

			offset += chunk_size;

			EVP_DigestUpdate(sha256_ctx, oob.data(), oob.length());
		}
	}
	catch(...)
	{
		std::cerr << std::endl;

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

	std::cerr << std::endl;
}

unsigned int E32If::write_file(std::string directory, std::string filename)
{
	int file_fd, chunk_size;
	unsigned int offset, length, attempt, attempts;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	char buffer[max_chunk_size];
	struct stat stat;
	std::string partition;
	EVP_MD_CTX *sha256_ctx;
	unsigned char sha256_hash[sha256_hash_size];
	unsigned int sha256_hash_length;
	std::string sha256_local_hash_text;
	std::string sha256_remote_hash_text;
	unsigned int pos;

	if(filename.empty())
		throw(hard_exception("filename required"));

	if(directory.empty())
		throw(hard_exception("destination directory required"));

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	if((pos = filename.find_last_of('/')) != std::string::npos)
		filename = filename.substr(pos + 1);

	filename = directory + "/" + filename;

	try
	{
		fstat(file_fd, &stat);
		length = stat.st_size;
		gettimeofday(&time_start, 0);

		sha256_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), (ENGINE *)0);

		for(offset = 0; offset < length;)
		{
			chunk_size = sizeof(buffer);

			if(chunk_size > max_chunk_size)
				chunk_size = max_chunk_size;

			if((chunk_size = ::read(file_fd, buffer, chunk_size)) <= 0)
				throw(hard_exception("i/o error in read"));

			command = (boost::format("fs-write %u %u %s") % ((offset == 0) ? 0 : 1) % chunk_size % filename).str();

			offset += chunk_size;

			EVP_DigestUpdate(sha256_ctx, buffer, chunk_size);

			attempts = 0;

			for(attempt = 4; attempt > 0; attempt--)
			{
				if(!debug)
				{
					int seconds, useconds;
					double duration;

					gettimeofday(&time_now, 0);

					seconds = time_now.tv_sec - time_start.tv_sec;
					useconds = time_now.tv_usec - time_start.tv_usec;
					duration = seconds + (useconds / 1000000.0);

					std::cerr << boost::format("sent %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u sectors, attempt %u, %3u%%     \r") %
							(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 4096) % (5 - attempt) % (offset * 100 / length);
					std::cerr.flush();
				}

				try
				{
					attempts += process(command, std::string(buffer, chunk_size), reply, nullptr, "OK file length: ([0-9]+)", &string_value, &int_value);

					if(int_value[0] != (int)offset)
						throw(hard_exception(boost::format("write file: remote file length [%u] != local offset [%u]") % int_value[0] % offset));

					break;
				}
				catch(const transient_exception &e)
				{
					if(verbose)
						std::cerr << std::endl << boost::format("write file failed: %s, reply: %s, retry") % e.what() % reply << std::endl;
					continue;
				}
			}

			if(attempt == 0)
				throw(hard_exception("write file: no more attempts"));
		}
	}
	catch(...)
	{
		std::cerr << std::endl;

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

	std::cerr << std::endl;

	return(length);
}

std::string E32If::perf_test_read() const
{
	enum { size = 4096, blocks = 1024 };
	unsigned int block;
	int seconds, useconds;
	double duration;
	timeval time_start, time_now;
	std::string reply;

	gettimeofday(&time_start, 0);

	for(block = 0; block < blocks; block++)
	{
		std::string ack("ACK");

		gettimeofday(&time_now, 0);
		seconds = time_now.tv_sec - time_start.tv_sec;
		useconds = time_now.tv_usec - time_start.tv_usec;
		duration = seconds + (useconds / 1000000.0);

		std::cerr << boost::format("received %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, sent %4u blocks, %2u%%     \r") %
				((block * size) / 1024) % duration % (((block * size) / 1024) / duration) % block % (block * 100 / blocks);
		std::cerr.flush();

		channel->send(ack, 1000000);
		channel->receive(reply, 1000000);
	}

	gettimeofday(&time_now, 0);
	seconds = time_now.tv_sec - time_start.tv_sec;
	useconds = time_now.tv_usec - time_start.tv_usec;
	duration = seconds + (useconds / 1000000.0);

	std::cerr << std::endl;

	return((boost::format("%.1f kbytes/second\n") % (((block * size) / 1024) / duration)).str());
}

std::string E32If::perf_test_write() const
{
	enum { size = 4096, blocks = 1024 };
	unsigned int block;
	int seconds, useconds;
	double duration;
	timeval time_start, time_now;
	std::string reply;

	gettimeofday(&time_start, 0);

	for(block = 0; block < blocks; block++)
	{
		std::string dummy(4096, 0xff);

		gettimeofday(&time_now, 0);
		seconds = time_now.tv_sec - time_start.tv_sec;
		useconds = time_now.tv_usec - time_start.tv_usec;
		duration = seconds + (useconds / 1000000.0);

		std::cerr << boost::format("sent %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, sent %4u blocks, %2u%%     \r") %
				((block * size) / 1024) % duration % (((block * size) / 1024) / duration) % block % (block * 100 / blocks);
		std::cerr.flush();

		channel->send(dummy, 1000000);
		channel->receive(reply, 1000000);
	}

	gettimeofday(&time_now, 0);
	seconds = time_now.tv_sec - time_start.tv_sec;
	useconds = time_now.tv_usec - time_start.tv_usec;
	duration = seconds + (useconds / 1000000.0);

	std::cerr << std::endl;

	return((boost::format("%.1f kbytes/second\n") % (((block * size) / 1024) / duration)).str());
}

void E32If::text(const std::string &id, unsigned int timeout, const std::string &text)
{
	std::string reply;

	if(id.length() == 0)
		throw(hard_exception("text command requires name/identifier"));

	if(text.length() == 0)
		throw(hard_exception("text command requires contents"));

	process((boost::format("display-page-add-text %s %u %s") % id % timeout % text).str(), "", reply, nullptr, "display-page-add-text added \".*", nullptr, nullptr);

	std::cerr << reply << std::endl;
}

void E32If::image(const std::string &id, unsigned int timeout, std::string directory, std::string filename, unsigned int x_size, unsigned int y_size)
{
	std::string reply;
	unsigned int pos, length;
	static const char tmp_dir_template[] = "/tmp/e32ifXXXXXX";
	char tmp_dir[256];
	std::string tmp_filename;
	std::string tmp_dir_filename;
	int rv;

	if(id.length() == 0)
		throw(hard_exception("image command requires name/identifier"));

	if(directory.length() == 0)
		directory = "/ramdisk";

	if(filename.length() == 0)
		throw(hard_exception("image command requires filename"));

	strlcpy(tmp_dir, tmp_dir_template, sizeof(tmp_dir));

	if(!mkdtemp(tmp_dir))
		throw(hard_exception("image command failed to create temporary directory"));

	tmp_filename = filename;

	if((pos = tmp_filename.find_last_of('/')) != std::string::npos)
		tmp_filename = tmp_filename.substr(pos + 1);

	if((pos = tmp_filename.find_last_of('.')) != std::string::npos)
		tmp_filename = tmp_filename.substr(0, pos);

	tmp_filename = (boost::format("%s.png") % tmp_filename).str();
	tmp_dir_filename = (boost::format("%s/%s") % tmp_dir % tmp_filename).str();

	if(verbose)
		std::cerr << "using temporary directory: " << tmp_dir  << ", file: " << tmp_dir_filename << std::endl;

	try
	{
		Magick::InitializeMagick(nullptr);

		Magick::Image image;
		Magick::Geometry newsize(x_size, y_size);

		newsize.aspect(true);

		image.read(filename);
		image.magick("png");

		if(debug)
			std::cerr << boost::format("image loaded from %s, %ux%u, version %s") % filename % image.columns() % image.rows() % image.magick() << std::endl;

		image.filterType(Magick::TriangleFilter);
		image.resize(newsize);

		if((image.columns() != x_size) || (image.rows() != y_size))
			throw(hard_exception("image magic resize failed"));

		image.write(tmp_dir_filename);
	}
	catch(const Magick::Error &error)
	{
		rv = unlink(tmp_dir_filename.c_str());

		if((debug || verbose) && (rv != 0))
			std::cerr << "image: unlink " << tmp_dir_filename << " failed" << std::endl;

		rv = rmdir(tmp_dir);

		if((debug || verbose) && (rv != 0))
			std::cerr << "image: rmdir " << tmp_dir << " failed" << std::endl;

		throw(hard_exception(boost::format("image: load failed: %s") % error.what()));
	}
	catch(const Magick::Warning &warning)
	{
		std::cerr << boost::format("image: %s") % warning.what() << std::endl;
	}

	length = write_file(directory, tmp_dir_filename);
	process((boost::format("display-page-add-image %s %u %s/%s %u") % id % timeout % directory % tmp_filename % length).str(), "", reply, nullptr, "display-page-add-image added \".*", nullptr, nullptr);

	std::cerr << reply << std::endl;

	rv = unlink(tmp_dir_filename.c_str());

	if((debug || verbose) && (rv != 0))
		std::cerr << "image: unlink " << tmp_dir_filename << " failed" << std::endl;

	rv = rmdir(tmp_dir);

	if((debug || verbose) && (rv != 0))
		std::cerr << "image: rmdir " << tmp_dir << " failed" << std::endl;
}
