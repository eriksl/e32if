#pragma once

#include "generic_socket.h"

#include <string>
#include <vector>

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

		std::string get();

	private:

		void _run(const std::vector<std::string> &);

        void text(const std::string &id, unsigned int timeout, const std::string &text_contents);
        void image(const std::string &id, unsigned int timeout, std::string directory, std::string filename, unsigned int x_size, unsigned int y_size);
		void ota(std::string filename) const;
		std::string send_text(std::string args) const;
		std::string perf_test_read() const;
		std::string perf_test_write() const;
		void read_file(std::string directory, std::string file);
		unsigned int write_file(std::string directory, std::string file);
		int process(const std::string &data, const std::string &oob_data,
				std::string &reply_data, std::string *reply_oob_data = nullptr,
				const char *match = nullptr, std::vector<std::string> *string_value = nullptr, std::vector<int> *int_value = nullptr,
				int timeout = 1500, unsigned int attempts = 8) const;

		std::string output;
		bool raw;
		bool verbose;
		bool debug;
		GenericSocket *channel;
		boost::random::mt19937 prn;
};
