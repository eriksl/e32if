#include <string>
#include <stdint.h>

// for packet_header_t
extern "C" {
#define __e32if__
#define assert_size(type, size) static_assert(sizeof(type) == size, "sizeof(" #type ") != " #size)
#define assert_field(name, field, offset) static_assert(offsetof(name, field) == offset)
#define attr_packed __attribute__ ((__packed__))
#define _Static_assert static_assert
#include "ota.h"
#undef assert_size
#undef attr_packed
}

class Packet
{
	friend class E32If;
	friend class Util;

	protected:

		Packet(Packet &) = delete;
		Packet();
		Packet(const std::string &data, const std::string &oob_data = "");
		void clear();
		void append_data(const std::string &);
		void append_oob_data(const std::string &);
		std::string encapsulate(bool raw, bool provide_checksum, bool request_checksum, unsigned int broadcast_group_mask, const uint32_t *transaction_id = nullptr);
		bool decapsulate(std::string *data, std::string *oob_data, bool verbose, bool *raw = nullptr, const uint32_t *transaction_id = nullptr);
		void query(bool &valid, bool &complete) noexcept;

	private:

		std::string data;
		std::string oob_data;
		packet_header_t packet_header;

		void clear_packet_header() noexcept;
		static uint32_t MD5_trunc_32(const std::string &data) noexcept;
};
