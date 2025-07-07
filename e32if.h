#pragma once

#include "generic_socket.h"

#include <string>
#include <vector>
#include <map>
#include <deque>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

class E32If
{
	public:

		E32If();
		E32If(const E32If &) = delete;
		~E32If();

		void run(const std::vector<std::string> &);
		void run(int argc, const char * const *argv);
		void run(const std::string &);

		std::string hostname() const;
		std::string get();

	private:

		static constexpr const char *dbus_service_id = "name.slagter.erik.espproxy";
		static constexpr const unsigned int sensor_data_timeout = 300;

		class ProxySensorDataKey
		{
			public:

				unsigned int module;
				unsigned int bus;
				std::string name;
				std::string type;

				int operator <(const ProxySensorDataKey &key) const
				{
					return(std::tie(this->module, this->bus, this->name, this->type) < std::tie(key.module, key.bus, key.name, key.type));
				}
		};

		struct ProxySensorDataEntry
		{
			time_t time;
			unsigned int id;
			unsigned int address;
			std::string unity;
			double value;
		};

		typedef std::map<ProxySensorDataKey, ProxySensorDataEntry> ProxySensorData;

		class ProxyThread
		{
			public:

				ProxyThread(E32If &, const std::vector<std::string> &signal_ids);
#ifdef SWIG
				operator ()();
#else
				__attribute__((noreturn)) void operator ()();
#endif

			private:

				E32If &e32if;
				std::vector<std::string> signal_ids;
		};

		struct ProxyCommandEntry
		{
			time_t time;
			std::string source;
			std::string command;
		};

		typedef std::deque<ProxyCommandEntry> ProxyCommands;

		void _run(const std::vector<std::string> &);

        void text(const std::string &id, unsigned int timeout, const std::string &text_contents);
        void image(const std::string &id, unsigned int timeout, std::string directory, std::string filename);
		void ota(std::string filename) const;
		std::string send_text(std::string args) const;
		std::string perf_test_read() const;
		std::string perf_test_write() const;
		void read_file(std::string directory, std::string file);
#ifdef SWIG
		void run_proxy(const std::vector<std::string> &);
#else
		__attribute__((noreturn)) void run_proxy(const std::vector<std::string> &);
#endif
		unsigned int write_file(std::string directory, std::string file);
		int process(const std::string &data, const std::string &oob_data,
				std::string &reply_data, std::string *reply_oob_data = nullptr,
				const char *match = nullptr, std::vector<std::string> *string_value = nullptr, std::vector<int> *int_value = nullptr,
				int timeout = 1500, unsigned int attempts = 8) const;

		std::string host;
		std::string output;
		std::string command_port;
		bool raw;
		bool verbose;
		bool debug;
		bool noprobe;
		bool proxy_connected;
		unsigned int x_size, y_size;
		GenericSocket *channel;
		boost::random::mt19937 prn;
		ProxySensorData proxy_sensor_data;
		ProxyCommands proxy_commands;
		ProxyThread *proxy_thread_class;
};
