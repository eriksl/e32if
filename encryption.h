#pragma once

#include <stdint.h>
#include <string>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

class Encryption
{
	public:

		Encryption();
		Encryption(const Encryption &) = delete;
		~Encryption();

		static std::string hash_to_text(std::string_view hash);

		static uint32_t crc32();
		static uint32_t crc32(uint32_t crc32_in, std::string_view data);

				void		sha256_init();
				void		sha256_update(std::string_view input);
				std::string	sha256_finish();
		static	std::string	sha256(std::string_view input);

				void		aes256_init(bool encrypt, bool key_is_binary, std::string key);
				std::string	aes256_update(std::string_view in);
				std::string	aes256_finish();
		static	std::string	aes256(bool encrypt, bool key_is_binary, std::string_view key, std::string_view input);

	private:
		
		static const uint32_t crc32_table[];

		bool sha256_ctx_active;
		mbedtls_md_context_t sha256_ctx;

		bool aes256_ctx_active;
		mbedtls_cipher_context_t aes256_ctx;
};
