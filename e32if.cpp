#include "e32if.h"
#include "exception.h"
#include "packet.h"
#include "udp_socket.h"
#include "tcp_socket.h"
#include "bt_socket.h"
#include "util.h"
#include "crypt.h"

#include <dbus-tiny.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/json.hpp>

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <Magick++.h>

using namespace std::chrono_literals;

namespace po = boost::program_options;

static const char *info_board_match_string = "firmware date: ([A-Za-z0-9: ]+), transport mtu: ([0-9]+), display area: ([0-9]+)x([0-9]+)";

E32If::E32If()
{
	channel = nullptr;
	raw = false;
	verbose = false;
	debug = false;
	mtu = 512;
	transport = transport_none;
	encryption_key = "default";
}

E32If::~E32If()
{
	if(channel)
	{
		delete channel;
		channel = nullptr;
	}
}

void E32If::process(const std::string &data, const std::string &oob_data, std::string &reply_data, std::string *reply_oob_data_in,
		const char *match, std::vector<std::string> *string_value, std::vector<int> *int_value, int timeout) const
{
	std::string packet;
	std::string reply_oob_data;
	boost::smatch capture;
	boost::regex re(match ? match : "");
	unsigned int captures;

	if((data.length() > this->mtu) || (oob_data.length() > this->mtu))
		throw(hard_exception((boost::format("process: data size too large %d/%d/%d") % data.length() % oob_data.length() % this->mtu)));

	packet = Packet::encapsulate(!this->raw, data, oob_data);

	if(debug)
		std::cout << Util::dumper("process: send data", packet) << std::endl;

	channel->send(packet, timeout);
	channel->receive(packet, timeout);

	if(debug)
		std::cout << Util::dumper("process: receive data", packet) << std::endl;

	Packet::decapsulate(!this->raw, packet, reply_data, reply_oob_data);

	if(reply_oob_data_in)
		*reply_oob_data_in = reply_oob_data;

	if(match && !boost::regex_match(reply_data, capture, re))
		throw(transient_exception(boost::format("received string does not match: \"%s\" vs. \"%s\"") % Util::dumper("reply", reply_data) % match));

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
				catch(...)
				{
					int_value->push_back(0);
				}
			}
		}
	}

	if(debug)
	{
		std::cout << Util::dumper("process: reply data", reply_data) << std::endl;

		if(reply_oob_data.length())
			std::cout << reply_oob_data.length () << " bytes OOB data received" << std::endl;
	}
}

std::string E32If::get()
{
	std::string rv = output;
	output.clear();

	return(rv);
}

std::string E32If::hostname() const
{
	return(this->host);
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

void E32If::_run(const std::vector<std::string> &argv_in)
{
	po::options_description	options("e32if usage");

	try
	{
		bool option_raw = false;
		bool option_noprobe = false;
		unsigned int force_mtu = 0;
		bool option_verbose = false;
		bool option_debug = false;
		std::vector<std::string> argv;
		std::vector<std::string> host_args;
		std::vector<std::string> proxy_signal_ids;
		std::string args;
		std::string option_command_port;
		std::string filename;
		std::string directory;
		std::string start_string;
		std::string transport_string = "udp";
		unsigned int timeout = 0;
		std::string page_id;
		std::string page_text;
		bool cmd_ota = false;
		bool cmd_text = false;
		bool cmd_image = false;
		bool cmd_write_file = false;
		bool cmd_read_file = false;
		bool cmd_proxy = false;
		bool cmd_perf_test_write = false;
		bool cmd_perf_test_read = false;
		unsigned int selected;

		for(std::vector<std::string>::const_iterator arg = argv_in.begin(); arg != argv_in.end(); arg++)
		{
			if(arg->length() && (arg->at(0) == '@'))
			{
				std::string include_filename;
				std::ifstream file;
				std::stringstream stream;
				std::string contents;
				typedef boost::char_separator<char> separator_t;
				separator_t separator(" \t\n");
				typedef boost::tokenizer<separator_t> tokenizer_t;
				tokenizer_t tokenizer(std::string(""), separator);

				include_filename = arg->substr(1, std::string::npos);

				file.open(include_filename);

				if(!file.is_open())
				{
					std::cerr << "warning: cannot open include file \"" << include_filename << "\"\n";
					continue;
				}

				stream << file.rdbuf();
				contents = stream.str();

				tokenizer.assign(contents);

				for(tokenizer_t::const_iterator token = tokenizer.begin(); token != tokenizer.end(); token++)
					argv.push_back(*token);

				file.close();
			}
			else
				argv.push_back(*arg);
		}

		options.add_options()
			("text",			po::bool_switch(&cmd_text)->implicit_value(true),						"add text page")
			("image",			po::bool_switch(&cmd_image)->implicit_value(true),						"add image page")
			("ota",				po::bool_switch(&cmd_ota)->implicit_value(true),						"OTA write")
			("write-file",		po::bool_switch(&cmd_write_file)->implicit_value(true),					"WRITE file")
			("read-file",		po::bool_switch(&cmd_read_file)->implicit_value(true),					"READ file")
			("proxy",			po::bool_switch(&cmd_proxy)->implicit_value(true),						"run proxy")
			("proxy-signal-id",	po::value<std::vector<std::string> >(&proxy_signal_ids),				"dbus signals to listen to")
			("host",			po::value<std::vector<std::string> >(&host_args)->required(),			"host to connect to")
			("verbose",			po::bool_switch(&option_verbose)->implicit_value(true),					"verbose output")
			("debug",			po::bool_switch(&option_debug)->implicit_value(true),					"packet trace etc.")
			("transport",		po::value<std::string>(&transport_string),								"select transport: udp (default), tcp or bluetooth (bt)")
			("page-id",			po::value<std::string>(&page_id),										"name of info page")
			("page-text",		po::value<std::string>(&page_text),										"contents of text page")
			("timeout",			po::value<unsigned int>(&timeout),										"timeout of text page in seconds")
			("filename",		po::value<std::string>(&filename),										"file")
			("directory",		po::value<std::string>(&directory),										"remote directory")
			("command-port",	po::value<std::string>(&option_command_port)->default_value("24"),		"command port to connect to")
			("raw",				po::bool_switch(&option_raw)->implicit_value(true),						"do not use packet encapsulation")
			("noprobe",			po::bool_switch(&option_noprobe)->implicit_value(true),					"skip probe for board information (mtu)")
			("mtu",				po::value<unsigned int>(&force_mtu),									"force mtu")
			("key",				po::value<std::string>(&encryption_key),								"set key for bluetooth")
			("pw",				po::bool_switch(&cmd_perf_test_write)->implicit_value(true),			"performance test WRITE")
			("pr",				po::bool_switch(&cmd_perf_test_read)->implicit_value(true),				"performance test READ");

		po::positional_options_description positional_options;
		positional_options.add("host", -1);

		po::variables_map varmap;
		auto parsed = po::command_line_parser(argv).options(options).positional(positional_options).run();
		po::store(parsed, varmap);
		po::store(po::parse_environment(options, "E32IF_"), varmap);
		po::notify(varmap);

		auto it = host_args.begin();
		this->host = *(it++);
		auto it1 = it;

		for(; it != host_args.end(); it++)
		{
			if(it != it1)
				args.append(" ");

			args.append(*it);
		}

		if((this->host.length() == 17) && (this->host.at(2) == ':') && (this->host.at(5) == ':') &&
					(this->host.at(8) == ':') && (this->host.at(11) == ':') && (this->host.at(14) == ':'))
			transport_string = "bluetooth";

		selected = 0;

		if(cmd_text)
			selected++;

		if(cmd_image)
			selected++;

		if(cmd_ota)
			selected++;

		if(cmd_read_file)
			selected++;

		if(cmd_proxy)
			selected++;

		if(cmd_write_file)
			selected++;

		if(cmd_perf_test_read)
		{
			option_command_port = "19"; // chargen
			selected++;
		}

		if(cmd_perf_test_write)
		{
			option_command_port = "9"; // discard
			selected++;
		}

		if(selected > 1)
			throw(hard_exception("specify one command"));

		if((transport_string == "bt") || (transport_string == "bluetooth"))
			this->transport = transport_bluetooth;
		else
			if(transport_string == "tcp")
				this->transport = transport_tcp_ip;
			else
				if(transport_string == "udp")
					this->transport = transport_udp_ip;
				else
					throw(hard_exception("unknown transport, use bluetooth/bt, udp or ip"));

		raw = option_raw;
		verbose = option_verbose;
		debug = option_debug;
		noprobe = option_noprobe;
		this->command_port = option_command_port;

		struct timeval tv;
		gettimeofday(&tv, nullptr);

		if(channel)
		{
			delete channel;
			channel = nullptr;
		}

		switch(this->transport)
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

		if(cmd_proxy)
			this->run_proxy(proxy_signal_ids, force_mtu);
		else
		{
			channel->connect(this->host, this->command_port, this->encryption_key);

			if(!noprobe)
			{
				std::string reply;
				std::vector<int> int_value;
				std::vector<std::string> string_value;

				process("info-board", "", reply, nullptr, info_board_match_string, &string_value, &int_value);

				if(force_mtu)
					this->mtu = force_mtu;
				else
					mtu = int_value[1];

				x_size = int_value[2];
				y_size = int_value[3];

				if(verbose)
				{
					std::cout << "transport: " << transport_string << std::endl;
					std::cout << "mtu: " << mtu << std::endl;
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
								this->image(page_id, timeout, directory, filename);
							else
								if(cmd_ota)
									this->ota(filename);
								else
									if(cmd_read_file)
										this->read_file(directory, filename);
									else
										if(cmd_write_file)
											this->write_file(directory, filename);
			channel->disconnect();
		}
	}
	catch(const DbusTinyException &e)
	{
		throw((boost::format("e32if: DbusTiny exception: %s\n%s") % e.what()).str());
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

void E32If::ota(std::string filename) const
{
	int file_fd, chunk_size;
	unsigned int offset, length;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	struct stat stat;
	std::string local_hash;
	std::string local_hash_text;
	std::string remote_hash_text;
	std::string buffer;
	std::string firmware_version;
	int seconds, useconds;
	unsigned int attempt;
	double duration;
	Crypt::SHA256 sha;

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

		process((boost::format("ota-start %u") % length).str(), "", reply, nullptr, "OK start write ota to partition ([0-9]+)/([a-zA-Z0-9_ -]+)", &string_value, &int_value, 10000);

		std::cout << (boost::format("start ota to [%u]: \"%s\", length: %u kB\n") % int_value[0] % string_value[1] % (length / 1024));

		sha.init();

		for(offset = 0; offset < length;)
		{
			if(offset == (length - 32))
				chunk_size = length - offset;
			else
				if((offset + this->mtu) >= (length - 32))
					chunk_size = length - 32 - offset;
				else
					chunk_size = this->mtu;

			buffer.resize(chunk_size);

			if((chunk_size = ::read(file_fd, buffer.data(), buffer.size())) <= 0)
				throw(hard_exception("i/o error in read"));

			buffer.resize(chunk_size);

			offset += chunk_size;

			if(offset < length)
				sha.update(buffer);

			command = (boost::format("ota-write %u %u") % chunk_size % ((offset >= length) ? 1 : 0)).str();

			gettimeofday(&time_now, 0);

			seconds = time_now.tv_sec - time_start.tv_sec;
			useconds = time_now.tv_usec - time_start.tv_usec;
			duration = seconds + (useconds / 1000000.0);

			std::cout << boost::format("sent %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u kB, %3u%%     \r") %
					(offset / 1024) %
					duration %
					(offset / 1024 / duration) %
					(offset / 1024) %
					(offset * 100 / length);
			std::cout.flush();

			process(command, buffer, reply, nullptr, "OK write ota", nullptr, nullptr, 10000);
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

	process("ota-finish", "", reply, nullptr, "OK finish ota, checksum: ([^ ]+)", &string_value);
	remote_hash_text = string_value[0];

	local_hash = sha.finish();
	local_hash_text = sha.hash_to_text(local_hash);

	if(local_hash_text != remote_hash_text)
		throw(hard_exception(boost::format("incorrect checksum, local: %s, remote: %s") % local_hash_text % remote_hash_text));

	std::cout << "checksum OK: " << local_hash_text << "\n";

	process((boost::format("ota-commit %s") % local_hash_text).str(), "", reply, nullptr, "OK commit ota");

	std::cout << "OTA write finished, rebooting" << std::endl;

	try
	{
		process("reset", "", reply, nullptr, nullptr, nullptr, nullptr, 0);
	}
	catch(const transient_exception &e)
	{
		if(verbose)
		{
			std::cout << "  reset returned transient error: " << e.what();
			std::cout << std::endl;
		}
	}
	catch(const hard_exception &e)
	{
		if(verbose)
		{
			std::cout << "  reset returned error: " << e.what();
			std::cout << std::endl;
		}
	}

	std::cout << "reconnecting";
	std::cout.flush();
	channel->disconnect();

	for(attempt = 0; attempt < 16; attempt++)
	{
		try
		{
			channel->connect();
			process("info-board", "", reply, nullptr, info_board_match_string, &string_value, &int_value);
			firmware_version = string_value[0];
		}
		catch(const transient_exception &e)
		{
			std::cout << ".";
			std::cout.flush();
			std::this_thread::sleep_for(std::chrono::seconds(1));
			continue;
		}

		break;
	}

	if(attempt >= 16)
		throw(hard_exception("ota: reconnect failed"));

	std::cout << "\nconnected\n";
	std::cout << "reboot finished, confirming boot slot" << std::endl;

	process("ota-confirm", "", reply, nullptr, "OK confirm ota");

	std::cout << boost::format("firmware version: %s") % firmware_version << std::endl;
}

std::string E32If::send_text(std::string arg) const
{
	std::string send_data;
	std::string reply;
	std::string reply_oob;
	std::string local_output;

	process(arg, "", reply, &reply_oob);

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

	return(local_output);
}

void E32If::read_file(std::string directory, std::string filename)
{
	int file_fd;
	unsigned int offset;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::string oob;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	std::string partition;
	Crypt::SHA256 sha;
	std::string local_hash_text;
	std::string remote_hash_text;
	unsigned int pos;
	unsigned int chunk_size;
	unsigned int received_chunk_size;
	int length;
	int seconds, useconds;
	double duration;

	if(filename.empty())
		throw(hard_exception("filename required"));

	if(directory.empty())
		throw(hard_exception("remote directory (fs) required"));

	if((file_fd = open(filename.c_str(), O_WRONLY | O_CREAT, 0666)) < 0)
		throw(hard_exception("can't create file"));

	if((pos = filename.find_last_of('/')) != std::string::npos)
		filename = filename.substr(pos + 1);

	filename = directory + "/" + filename;

	try
	{
		chunk_size = this->mtu;

		gettimeofday(&time_start, 0);

		sha.init();

		for(offset = 0;;)
		{
			command = (boost::format("fs-read %u %s %s") % chunk_size % offset % filename).str();

			if(!debug)
			{
				gettimeofday(&time_now, 0);

				seconds = time_now.tv_sec - time_start.tv_sec;
				useconds = time_now.tv_usec - time_start.tv_usec;
				duration = seconds + (useconds / 1000000.0);

				std::cout << boost::format("received %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, received %3u kB,       \r") %
						(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 1024);
					std::cout.flush();
			}

			oob.clear();
			process(command, "", reply, &oob, "OK chunk read: ([0-9]+)", nullptr, &int_value);
			received_chunk_size = int_value[0];

			if(received_chunk_size != oob.length())
				throw(hard_exception(boost::format("chunk size [%u] differs from oob size [%u]") % received_chunk_size % oob.length()));

			if(received_chunk_size == 0)
				break;

			if((length = ::write(file_fd, oob.data(), oob.length())) != (int)oob.length())
				throw(hard_exception("i/o error in write"));

			offset += length;

			sha.update(oob);
		}
	}
	catch(...)
	{
		std::cout << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	local_hash_text = sha.hash_to_text(sha.finish());

	process(std::string("fs-checksum ") + filename, "", reply, nullptr, "OK checksum: ([0-9a-f]+)", &string_value, &int_value);

	remote_hash_text = string_value[0];

	if(local_hash_text != remote_hash_text)
		throw(hard_exception(boost::format("checksum failed: SHA256 hash differs, local: %u, remote: %s") % local_hash_text % remote_hash_text));

	std::cout << std::endl;
}

unsigned int E32If::write_file(std::string directory, std::string filename)
{
	std::string swap_filename;
	int file_fd;
	unsigned int offset, length;
	struct timeval time_start, time_now;
	std::string command;
	std::string reply;
	std::vector<std::string> string_value;
	std::vector<int> int_value;
	struct stat stat;
	std::string partition;
	Crypt::SHA256 sha;
	std::string local_hash_text;
	std::string remote_hash_text;
	unsigned int pos;
	unsigned int chunk_size;
	int read_chunk_size;
	std::string buffer;
	int seconds, useconds;
	double duration;

	if(filename.empty())
		throw(hard_exception("filename required"));

	if(directory.empty())
		throw(hard_exception("remote directory (fs) required"));

	if((file_fd = open(filename.c_str(), O_RDONLY, 0)) < 0)
		throw(hard_exception("file not found"));

	if((pos = filename.find_last_of('/')) != std::string::npos)
		filename = filename.substr(pos + 1);

	filename = directory + "/" + filename;
	swap_filename = filename + ".tmp";

	try
	{
		chunk_size = this->mtu;
		buffer.resize(chunk_size);

		fstat(file_fd, &stat);
		length = stat.st_size;
		gettimeofday(&time_start, 0);

		sha.init();

		process((boost::format("fs-rename %s %s") % filename % swap_filename).str(), std::string(""), reply);

		for(offset = 0; offset < length;)
		{
			if((read_chunk_size = ::read(file_fd, buffer.data(), buffer.size())) <= 0)
				throw(hard_exception("i/o error in read"));

			buffer.resize(read_chunk_size);

			command = (boost::format("fs-write %u %u %s") % ((offset == 0) ? 0 : 1) % read_chunk_size % swap_filename).str();

			offset += read_chunk_size;

			sha.update(buffer);

			if(!debug)
			{
				gettimeofday(&time_now, 0);

				seconds = time_now.tv_sec - time_start.tv_sec;
				useconds = time_now.tv_usec - time_start.tv_usec;
				duration = seconds + (useconds / 1000000.0);

				std::cout << boost::format("sent %4u kbytes in %3.0f seconds at rate %3.0f kbytes/s, sent %3u kB, %3u%%     \r") %
						(offset / 1024) % duration % (offset / 1024 / duration) % (offset / 1024) % (offset * 100 / length);
				std::cout.flush();
			}

			process(command, buffer, reply, nullptr, "OK file length: ([0-9]+)", &string_value, &int_value);

			if(int_value[0] != (int)offset)
				throw(hard_exception(boost::format("remote file length [%u] != local offset [%u]\n") % int_value[0] % offset));
		}
	}
	catch(...)
	{
		std::cout << std::endl;

		close(file_fd);
		throw;
	}

	close(file_fd);

	local_hash_text = sha.hash_to_text(sha.finish());

	process(std::string("fs-checksum ") + swap_filename, "", reply, nullptr, "OK checksum: ([0-9a-f]+)", &string_value, &int_value);

	remote_hash_text = string_value[0];

	if(local_hash_text != remote_hash_text)
	{
		process((boost::format("fs-remove %s %s") % swap_filename).str(), std::string(""), reply);
		throw(hard_exception(boost::format("checksum failed: SHA256 hash differs, local: %u, remote: %s") % local_hash_text % remote_hash_text));
	}

	process((boost::format("fs-rename %s %s") % swap_filename % filename).str(), std::string(""), reply);

	std::cout << std::endl;

	return(length);
}

E32If::ProxyThread::ProxyThread(E32If &e32if_in, const std::vector<std::string> &signal_ids_in) : e32if(e32if_in), signal_ids(signal_ids_in)
{
}

void E32If::ProxyThread::operator()()
{
	std::string message_type;
	std::string message_interface;
	std::string message_method;
	std::string error;
	std::string reply;
	std::string time_string;
	std::string service = (boost::format("%s.%s") % dbus_service_id % e32if.hostname()).str();

	try
	{
		DbusTinyServer dbus_tiny_server(service);

		for(const auto &it : signal_ids)
		{
			if(e32if.verbose)
				std::cout << "adding signal filter: " << it << std::endl;
			dbus_tiny_server.register_signal((boost::format("%s.%s.%s") % dbus_service_id % "signal" % it).str());
		}

		for(;;)
		{
			try
			{
				dbus_tiny_server.get_message(message_type, message_interface, message_method);

				if(message_type == "method call")
				{
					if(e32if.verbose)
						std::cout << boost::format("message received, interface: %s, method: %s\n") % message_interface % message_method;

					if(message_interface == "org.freedesktop.DBus.Introspectable")
					{
						if(message_method == "Introspect")
						{
							reply += std::string("") +
										"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n" +
										"<node>\n" +
										"	<interface name=\"org.freedesktop.DBus.Introspectable\">\n" +
										"		<method name=\"Introspect\">\n" +
										"			<arg name=\"xml\" type=\"s\" direction=\"out\"/>\n" +
										"		</method>\n" +
										"	</interface>\n" +
										"	<interface name=\"" + service + "\">\n" +
										"		<method name=\"dump\">\n" +
										"			<arg name=\"info\" type=\"s\" direction=\"out\"/>\n" +
										"		</method>\n" +
										"		<method name=\"get_sensor_data\">\n" +
										"			<arg name=\"module\" type=\"u\" direction=\"in\"/>\n" +
										"			<arg name=\"bus\" type=\"u\" direction=\"in\"/>\n" +
										"			<arg name=\"name\" type=\"s\" direction=\"in\"/>\n" +
										"			<arg name=\"type\" type=\"s\" direction=\"in\"/>\n" +
										"			<arg name=\"time\" type=\"t\" direction=\"out\"/>\n" +
										"			<arg name=\"id\" type=\"u\" direction=\"out\"/>\n" +
										"			<arg name=\"address\" type=\"u\" direction=\"out\"/>\n" +
										"			<arg name=\"unity\" type=\"s\" direction=\"out\"/>\n" +
										"			<arg name=\"value\" type=\"d\" direction=\"out\"/>\n" +
										"		</method>\n" +
										"		<method name=\"push_command\">\n" +
										"			<arg name=\"command\" type=\"s\" direction=\"in\"/>\n" +
										"			<arg name=\"status\" type=\"s\" direction=\"out\"/>\n" +
										"		</method>\n" +
										"	</interface>\n";

							for(const auto &it : signal_ids)
							{
								reply += std::string("") +
										"	<interface name=\"" + dbus_service_id + ".signal." + it + "\">\n" +
										"		<signal name=\"push_command\">\n" +
										"			<arg name=\"command\" type=\"s\"/>\n" +
										"		</signal>\n" +
										"	</interface>\n";
							}

							reply += "</node>\n";

							dbus_tiny_server.send_string(reply);

							reply.clear();
						}
						else
							throw(transient_exception(dbus_tiny_server.inform_error(std::string("unknown introspection method called"))));
					}
					else
					{
						if((message_interface == dbus_service_id) || (message_interface == ""))
						{
							if(message_method == "dump")
							{
								reply += (boost::format("CONNECTED: %s\n\n") % (e32if.proxy_connected ? "yes" : "no")).str();
								reply += "SENSOR DATA\n\n";

								for(const auto &it : e32if.proxy_sensor_data)
								{
									Util::time_to_string(time_string, it.second.time);

									reply += (boost::format("> %1u %1u %-16s %-16s / %2u @ %02x %8.2f %-3s %s\n") %
												it.first.module % it.first.bus % it.first.name % it.first.type %
												it.second.id % it.second.address % it.second.value % it.second.unity % time_string).str();
								}

								reply += "\nCOMMANDS\n\n";

								for(const auto &it : e32if.proxy_commands)
								{
									Util::time_to_string(time_string, it.time);

									reply += (boost::format("> %s from %s at %s\n") % it.command % it.source % time_string).str();
								}

								dbus_tiny_server.send_string(reply);

								reply.clear();
							}
							else
							{
								if(message_method == "get_sensor_data")
								{
									unsigned int module;
									unsigned int bus;
									std::string name;
									std::string type;
									ProxySensorDataKey key;
									ProxySensorData::const_iterator it;

									dbus_tiny_server.receive_uint32_uint32_string_string(module, bus, name, type);

									key.module = module;
									key.bus = bus;
									key.name = name;
									key.type = type;

									if((it = e32if.proxy_sensor_data.find(key)) == e32if.proxy_sensor_data.end())
										throw(transient_exception(dbus_tiny_server.inform_error((boost::format("not found: %u/%u/%s/%s") % key.module % key.bus % key.name % key.type).str())));
									dbus_tiny_server.send_uint64_uint32_uint32_string_double(it->second.time, it->second.id, it->second.address, it->second.unity, it->second.value);
								}
								else
								{
									if(message_method == "push_command")
									{
										std::string command;
										ProxyCommandEntry entry;

										command = dbus_tiny_server.receive_string();

										entry.time = time((time_t *)0);
										entry.source = "message";
										entry.command = command;

										if(e32if.proxy_connected)
											e32if.proxy_commands.push_back(entry);

										dbus_tiny_server.send_string("ok");
									}
									else
										throw(transient_exception(dbus_tiny_server.inform_error(std::string("unknown method called"))));
								}
							}
						}
						else
							throw(transient_exception(dbus_tiny_server.inform_error((boost::format("message not for our interface: %s") % message_interface).str())));
					}
				}
				else if(message_type == "signal")
				{
					if(e32if.verbose)
						std::cout << boost::format("signal received, interface: %s, method: %s\n") % message_interface % message_method;

					if((message_interface == "org.freedesktop.DBus") && (message_method == "NameAcquired"))
					{
						if(e32if.verbose)
							std::cout << "name on dbus acquired\n";
					}
					else
					{
						std::vector<std::string>::const_iterator it;

						for(it = signal_ids.begin(); it != signal_ids.end(); it++)
						{
							std::string interface_check = (boost::format("%s.%s.%s") % dbus_service_id % "signal" % *it).str();

							if(message_interface == interface_check)
								break;
						}

						if(it == signal_ids.end())
							throw(transient_exception(dbus_tiny_server.inform_error(std::string("signal to unknown interface received"))));

						if(message_method == "push_command")
						{
							std::string command;
							ProxyCommandEntry entry;

							command = dbus_tiny_server.receive_string();

							entry.time = time((time_t *)0);
							entry.source = "signal";
							entry.command = command;

							if(e32if.proxy_connected)
								e32if.proxy_commands.push_back(entry);
						}
						else
							throw(transient_exception(dbus_tiny_server.inform_error(std::string("unknown signal received"))));
					}
				}
				else
					throw(transient_exception(boost::format("message of unknown type: %u") % message_type));
			}
			catch(const transient_exception &e)
			{
				std::cerr << boost::format("warning: %s\n") % e.what();
			}

			dbus_tiny_server.reset();
		}
	}
	catch(const DbusTinyException &e)
	{
		std::cerr << boost::format("e32if proxy: DbusTiny exception: %s\n") % e.what();
		exit(-1);
	}
	catch(const hard_exception &e)
	{
		std::cerr << boost::format("e32if proxy: fatal: %s\n") % e.what();
		exit(-1);
	}
}

void E32If::run_proxy(const std::vector<std::string> &proxy_signal_ids, unsigned int force_mtu)
{
	std::string reply, line, time_string;
	ProxySensorDataKey key;
	ProxySensorDataEntry data;
	ProxyCommandEntry entry;
	boost::json::parser json;
	boost::json::object object;
	std::vector<int> int_value;
	std::vector<std::string> string_value;
	bool rerun;
	std::chrono::steady_clock::time_point previous_sensor_run;
	std::chrono::steady_clock::time_point current_sensor_run;

	previous_sensor_run = current_sensor_run = std::chrono::steady_clock::now();

	proxy_connected = false;

	proxy_thread_class = new ProxyThread(*this, proxy_signal_ids);
	std::thread proxy_thread(*proxy_thread_class);
	proxy_thread.detach();

	for(;;)
	{
		try
		{
			channel->connect(this->host, this->command_port, this->encryption_key);

			if(!noprobe)
			{
				process("info-board", "", reply, nullptr, info_board_match_string, &string_value, &int_value);

				if(force_mtu)
					mtu = force_mtu;
				else
					mtu = int_value[1];

				x_size = int_value[2];
				y_size = int_value[3];

				if(verbose)
				{
					std::cout << "mtu: " << mtu << std::endl;
					std::cout << "display dimensions: " << x_size << "x" << y_size << std::endl;
				}
			}
			else
			{
				x_size = 0;
				y_size = 0;
			}
		}
		catch(const hard_exception &e)
		{
			std::cerr << boost::format("get info: hard exception: %s\n") % e.what();
			std::this_thread::sleep_for(std::chrono::seconds(10));
			continue;
		}
		catch(const transient_exception &e)
		{
			std::cerr << boost::format("get info: transient exception: %s\n") % e.what();
			std::this_thread::sleep_for(std::chrono::seconds(10));
			continue;
		}

		break;
	}

	proxy_connected = true;

	for(;;)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));

		current_sensor_run = std::chrono::steady_clock::now();
		auto duration = current_sensor_run - previous_sensor_run;

		if(duration >= std::chrono::duration<int>(30s))
		{
			previous_sensor_run = current_sensor_run;

			try
			{
				process("sj", "", reply, nullptr, nullptr, nullptr, nullptr);
			}
			catch(const transient_exception &e)
			{
				std::cerr << "sensor data retrieve: transient error: " << e.what() << std::endl;
				continue;
			}

			json.reset();

			try
			{
				json.write(reply);
				object = json.release().as_object();

				for(auto const &it_0 : object)
				{
					for(auto const &it_1 : it_0.value().as_array())
					{
						for(auto const &it_2 : it_1.as_object())
						{
							if(it_2.key() == "module")
								key.module = it_2.value().as_int64();
							else if(it_2.key() == "bus")
								key.bus = it_2.value().as_int64();
							else if(it_2.key() == "name")
								key.name = it_2.value().as_string();
							else if(it_2.key() == "values")
							{
								for(auto const &it_3 : it_2.value().as_array())
								{
									for(auto const &it_4 : it_3.as_object())
									{
										if(it_4.key() == "type")
											key.type = it_4.value().as_string();
										else if(it_4.key() == "id")
											data.id = it_4.value().as_int64();
										else if(it_4.key() == "address")
											data.address = it_4.value().as_int64();
										else if(it_4.key() == "unity")
											data.unity = it_4.value().as_string();
										else if(it_4.key() == "value")
											data.value = it_4.value().as_double();
										else if(it_4.key() == "time")
											data.time = it_4.value().as_int64();
									}

									proxy_sensor_data[key] = data;
								}
							}
						}
					}
				}
			}
			catch(const boost::system::system_error &e)
			{
				std::cerr << "json: " << e.what() << std::endl;
				std::cerr << "  reply: " << reply << std::endl;
			}
		}

		time_t time_obsolete = time(nullptr) - sensor_data_timeout;

		while(rerun)
		{
			rerun = false;

			for(const auto &ref : proxy_sensor_data)
			{
				if(ref.second.time < time_obsolete)
				{
					proxy_sensor_data.erase(ref.first);
					rerun = true;
					break;
				}
			}
		}

		if(proxy_commands.size() > 0)
		{
			entry = proxy_commands.back();
			proxy_commands.pop_back();

			if((time((time_t *)0) - entry.time) > (5 * 60))
			{
				if(verbose)
					std::cout << "dropping timed out command: " << entry.command << ", timestamp: " << entry.time << std::endl;
			}
			else
			{
				try
				{
					process(entry.command, "", reply);
				}
				catch(const transient_exception &e)
				{
					std::cerr << "command push: transient exception: " << e.what();
					std::this_thread::sleep_for(std::chrono::seconds(1));
					continue;
				}
				catch(const hard_exception &e)
				{
					std::cerr << "command push: hard exception: " << e.what();
					std::this_thread::sleep_for(std::chrono::seconds(1));
					continue;
				}

				if(verbose)
					std::cout << "sent: " << entry.command << ", reply: " << reply << std::endl;
			}
		}
	}
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

		std::cout << boost::format("received %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, sent %4u blocks, %2u%%     \r") %
				((block * size) / 1024) % duration % (((block * size) / 1024) / duration) % block % (block * 100 / blocks);
		std::cout.flush();

		channel->send(ack, 1000000);
		channel->receive(reply, 1000000);
	}

	gettimeofday(&time_now, 0);
	seconds = time_now.tv_sec - time_start.tv_sec;
	useconds = time_now.tv_usec - time_start.tv_usec;
	duration = seconds + (useconds / 1000000.0);

	std::cout << std::endl;

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

		std::cout << boost::format("sent %4u kbytes in %2.0f seconds at rate %3.0f kbytes/s, sent %4u blocks, %2u%%     \r") %
				((block * size) / 1024) % duration % (((block * size) / 1024) / duration) % block % (block * 100 / blocks);
		std::cout.flush();

		channel->send(dummy, 1000000);
		channel->receive(reply, 1000000);
	}

	gettimeofday(&time_now, 0);
	seconds = time_now.tv_sec - time_start.tv_sec;
	useconds = time_now.tv_usec - time_start.tv_usec;
	duration = seconds + (useconds / 1000000.0);

	std::cout << std::endl;

	return((boost::format("%.1f kbytes/second\n") % (((block * size) / 1024) / duration)).str());
}

void E32If::text(const std::string &id, unsigned int timeout, const std::string &text)
{
	std::string reply;

	if(id.length() == 0)
		throw(hard_exception("text command requires name/identifier"));

	if(text.length() == 0)
		throw(hard_exception("text command requires contents"));

	process((boost::format("display-page-add-text %s %u %s") % id % timeout % text).str(), "", reply, nullptr, "display-page-add-text added \".*");

	std::cout << reply << std::endl;
}

void E32If::image(const std::string &id, unsigned int timeout, std::string directory, std::string filename)
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
		std::cout << "using temporary directory: " << tmp_dir  << ", file: " << tmp_dir_filename << std::endl;

	try
	{
		Magick::InitializeMagick(nullptr);

		Magick::Image image;
		Magick::Geometry newsize(x_size, y_size);

		newsize.aspect(true);

		image.read(filename);
		image.magick("png");

		if(verbose)
			std::cout << boost::format("image loaded from %s, %ux%u, version %s") % filename % image.columns() % image.rows() % image.magick() << std::endl;

		image.filterType(Magick::TriangleFilter);
		image.resize(newsize);

		if((image.columns() != x_size) || (image.rows() != y_size))
			throw(hard_exception("image magic resize failed"));

		image.write(tmp_dir_filename);
	}
	catch(const Magick::Error &error)
	{
		rv = unlink(tmp_dir_filename.c_str());

		if(verbose && (rv != 0))
			std::cout << "image: unlink " << tmp_dir_filename << " failed" << std::endl;

		rv = rmdir(tmp_dir);

		if(verbose && (rv != 0))
			std::cout << "image: rmdir " << tmp_dir << " failed" << std::endl;

		throw(hard_exception(boost::format("image: load failed: %s") % error.what()));
	}
	catch(const Magick::Warning &warning)
	{
		std::cerr << boost::format("image: %s") % warning.what() << std::endl;
	}

	length = write_file(directory, tmp_dir_filename);
	process((boost::format("display-page-add-image %s %u %s/%s %u") % id % timeout % directory % tmp_filename % length).str(), "", reply, nullptr, "display-page-add-image added \".*");

	std::cout << reply << std::endl;

	rv = unlink(tmp_dir_filename.c_str());

	if(verbose && (rv != 0))
		std::cout << "image: unlink " << tmp_dir_filename << " failed" << std::endl;

	rv = rmdir(tmp_dir);

	if(verbose && (rv != 0))
		std::cout << "image: rmdir " << tmp_dir << " failed" << std::endl;
}
