/*
 * xcitools - Manage XCI from command line
 * Copyright (C) 2018 Timothy Redaelli
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef __MINGW32__
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "crc32/Crc32.h"

#if SIZE_MAX > UINT32_MAX
#define WANTS_MMAP
#else
#warning mmap is not used
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#if defined(__GNUC__) || defined(__clang__)
#define _htole32(x) __builtin_bswap32(x)
#else
#define _htole32(num) (((num >> 24) & 0xff)	| \
			((num << 8) & 0xff0000)	| \
			((num >> 8) & 0xff00)	| \
			((num << 24) & 0xff000000))
#endif
#else
#define _htole32(x) (x)
#endif

#ifdef WANTS_MMAP
#ifdef __WIN32__
#include "windows-mmap.h"
#else
#include <sys/mman.h>
#endif
#endif

#define BUFFER_SIZE	(4 * 1024)
static uint8_t buffer[BUFFER_SIZE];

enum modes { trim, pad, crc32, md5, sha1 };

static off_t get_ROMsize(uint32_t cart_type)
{
	off_t ret;
	switch (cart_type) {
	case 0xF8:
		ret = 2;
		break;
	case 0xF0:
		ret = 4;
		break;
	case 0xE0:
		ret = 8;
		break;
	case 0xE1:
		ret = 16;
		break;
	case 0xE2:
		ret = 32;
		break;
	default:
		return 0;
	}
	return (ret * 1024 - (ret * 0x48)) * 1024 * 1024;
}

#ifdef WANTS_MMAP
static inline void openssl_hash(const char *digestname, uint8_t *addr,
				off_t TRIM_size, off_t ROM_size,
				uint8_t *TRIM_hash, uint8_t *ROM_hash)
{
	EVP_MD_CTX *m_context_trim = EVP_MD_CTX_create();
	EVP_MD_CTX *m_context_rom = EVP_MD_CTX_create();
	EVP_DigestInit_ex(m_context_trim, EVP_get_digestbyname(digestname), NULL);
	EVP_DigestUpdate(m_context_trim, addr, TRIM_size);
	EVP_MD_CTX_copy_ex(m_context_rom, m_context_trim);
	for (off_t i = TRIM_size; i < ROM_size; i += BUFFER_SIZE) {
		off_t bytesLeft = ROM_size - i;
		size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

		EVP_DigestUpdate(m_context_rom, buffer, chunk);
	}
	EVP_DigestFinal_ex(m_context_trim, TRIM_hash, NULL);
	EVP_DigestFinal_ex(m_context_rom, ROM_hash, NULL);
	EVP_MD_CTX_destroy(m_context_trim);
	EVP_MD_CTX_destroy(m_context_rom);
}

static void manage_xci(const enum modes mode, const char *path)
{
	uint8_t cart_size;
	off_t ROM_size, TRIM_size;
	uint32_t TMP_size, ROM_crc32 = 0, TRIM_crc32 = 0;
	uint8_t ROM_md5[MD5_DIGEST_LENGTH], TRIM_md5[MD5_DIGEST_LENGTH];
	uint8_t ROM_sha1[SHA_DIGEST_LENGTH], TRIM_sha1[SHA_DIGEST_LENGTH];
	off_t FILE_size, i;
	uint8_t *addr;
	int fd = open(path, O_RDONLY, 0);

	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if ((FILE_size = lseek(fd, 0L, SEEK_END)) < 0) {
		perror("lseek");
		exit(EXIT_FAILURE);
	}
	if (FILE_size < 0x200) {
		exit(EXIT_FAILURE);
	}
	addr = (uint8_t *)mmap(NULL, FILE_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	cart_size = addr[0x10D];
	ROM_size = get_ROMsize(cart_size);
	if (ROM_size == 0) {
		fprintf(stderr, "Could not determine size for ROM %s\n.", path);
		exit(EXIT_FAILURE);
	}
	memcpy(&TMP_size, &addr[0x118], 4);
	TRIM_size = (off_t)_htole32(TMP_size) * 512 + 512;
	if (FILE_size != TRIM_size && FILE_size != ROM_size) {
		fprintf(stderr, "ROM %s is improperly trimmed or padded\n",
			path);
		exit(EXIT_FAILURE);
	}

	switch (mode) {
	case trim:
		munmap(addr, FILE_size);
		close(fd);
		truncate(path, TRIM_size);
		break;

	case pad:
		munmap(addr, FILE_size);
		close(fd);
		fd = open(path, O_APPEND, 0);
		for (i = TRIM_size; i < ROM_size; i += BUFFER_SIZE) {
			off_t bytesLeft = ROM_size - i;
			size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

			write(fd, buffer, chunk);
		}
		close(fd);
		break;

	case crc32:
		for (i = 0; i < TRIM_size; i += BUFFER_SIZE) {
			off_t bytesLeft = TRIM_size - i;
			size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

			TRIM_crc32 = crc32_fast(addr + i, chunk, TRIM_crc32);
		}
		munmap(addr, FILE_size);
		close(fd);
		ROM_crc32 = TRIM_crc32;
		for (i = TRIM_size; i < ROM_size; i += BUFFER_SIZE) {
			off_t bytesLeft = ROM_size - i;
			size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

			ROM_crc32 = crc32_fast(buffer, chunk, ROM_crc32);
		}
		printf("File %strimmed\n", FILE_size == TRIM_size ? "" : "not ");
		printf("%08X  %s // trim size: %jd\n", TRIM_crc32, path, (intmax_t)TRIM_size);
		printf("%08X  %s // cart size: %jd\n", ROM_crc32, path, (intmax_t)ROM_size);
		break;

	case md5:
		openssl_hash("md5", addr, TRIM_size, ROM_size, TRIM_md5, ROM_md5);
		munmap(addr, FILE_size);
		close(fd);
		printf("File %strimmed\n", FILE_size == TRIM_size ? "" : "not ");
		for (off_t i = 0; i < MD5_DIGEST_LENGTH; i++)
			printf("%.2X", TRIM_md5[i]);
		printf("  %s // trim size: %jd\n", path, (intmax_t)TRIM_size);
		for (off_t i = 0; i < MD5_DIGEST_LENGTH; i++)
			printf("%.2X", ROM_md5[i]);
		printf("  %s // cart size: %jd\n", path, (intmax_t)ROM_size);
		break;

	case sha1:
		openssl_hash("sha1", addr, TRIM_size, ROM_size, TRIM_sha1, ROM_sha1);
		munmap(addr, FILE_size);
		close(fd);
		printf("File %strimmed\n", FILE_size == TRIM_size ? "" : "not ");
		for (off_t i = 0; i < SHA_DIGEST_LENGTH; i++)
			printf("%.2X", TRIM_sha1[i]);
		printf("  %s // trim size: %jd\n", path, (intmax_t)TRIM_size);
		for (off_t i = 0; i < SHA_DIGEST_LENGTH; i++)
			printf("%.2X", ROM_sha1[i]);
		printf("  %s // cart size: %jd\n", path, (intmax_t)ROM_size);
		break;
	}
}
#else
static inline void openssl_hash(const char *digestname, FILE *fd,
				off_t TRIM_size, off_t ROM_size,
				uint8_t *TRIM_hash, uint8_t *ROM_hash)
{
	EVP_MD_CTX *m_context_trim = EVP_MD_CTX_create();
	EVP_MD_CTX *m_context_rom = EVP_MD_CTX_create();
	EVP_DigestInit_ex(m_context_trim, EVP_get_digestbyname(digestname), NULL);
	for (off_t i = 0; i < TRIM_size; i += BUFFER_SIZE) {
		off_t bytesLeft = TRIM_size - i;
		size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

		fread(buffer, 1, BUFFER_SIZE, fd);
		EVP_DigestUpdate(m_context_trim, buffer, chunk);
	}
	EVP_MD_CTX_copy_ex(m_context_rom, m_context_trim);
	for (off_t i = TRIM_size; i < ROM_size; i += BUFFER_SIZE) {
		off_t bytesLeft = ROM_size - i;
		size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

		EVP_DigestUpdate(m_context_rom, buffer, chunk);
	}
	EVP_DigestFinal_ex(m_context_trim, TRIM_hash, NULL);
	EVP_DigestFinal_ex(m_context_rom, ROM_hash, NULL);
	EVP_MD_CTX_destroy(m_context_trim);
	EVP_MD_CTX_destroy(m_context_rom);
}

static void manage_xci(const enum modes mode, const char *path)
{
	uint8_t cart_size;
	off_t ROM_size, TRIM_size;
	uint32_t TMP_size, ROM_crc32 = 0, TRIM_crc32 = 0;
	uint8_t ROM_md5[MD5_DIGEST_LENGTH], TRIM_md5[MD5_DIGEST_LENGTH];
	uint8_t ROM_sha1[SHA_DIGEST_LENGTH], TRIM_sha1[SHA_DIGEST_LENGTH];
	off_t FILE_size, i;
	FILE *fd = fopen(path, "rb");

	if (fd == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	if (fseeko(fd, 0L, SEEK_END) < 0) {
		perror("fseeko");
		exit(EXIT_FAILURE);
	}
	FILE_size = ftello(fd);
	if (FILE_size < 0x200) {
		exit(EXIT_FAILURE);
	}
	if (fseeko(fd, 0x10D, SEEK_SET) < 0) {
		perror("fseeko");
		exit(EXIT_FAILURE);
	}
	if (fread(&cart_size, 1, 1, fd) != 1) {
		perror("fread");
		exit(EXIT_FAILURE);
	}
	ROM_size = get_ROMsize(cart_size);
	if (ROM_size == 0) {
		fprintf(stderr, "Could not determine size for ROM %s\n.", path);
		exit(EXIT_FAILURE);
	}
	if (fseeko(fd, 0x118, SEEK_SET) < 0) {
		perror("fseeko");
		exit(EXIT_FAILURE);
	}
	if (fread(&TMP_size, 1, 4, fd) != 4) {
		perror("fread");
		exit(EXIT_FAILURE);
	}
	TRIM_size = (off_t)_htole32(TMP_size) * 512 + 512;
	if (FILE_size != TRIM_size && FILE_size != ROM_size) {
		fprintf(stderr, "ROM %s is improperly trimmed or padded\n",
			path);
		exit(EXIT_FAILURE);
	}

	switch (mode) {
	case trim:
		fclose(fd);
		truncate(path, TRIM_size);
		break;

	case pad:
		fclose(fd);
		fd = fopen(path, "ab");
		memset(buffer, 0xFF, BUFFER_SIZE);
		for (i = TRIM_size; i < ROM_size; i += BUFFER_SIZE) {
			off_t bytesLeft = ROM_size - i;
			size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

			fwrite(buffer, 1, chunk, fd);
		}
		fclose(fd);
		break;

	case crc32:
		fseeko(fd, 0x0, SEEK_SET);
		for (i = 0; i < TRIM_size; i += BUFFER_SIZE) {
			off_t bytesLeft = TRIM_size - i;
			size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

			fread(buffer, 1, BUFFER_SIZE, fd);
			TRIM_crc32 = crc32_fast(buffer, chunk, TRIM_crc32);
		}
		fclose(fd);
		memset(buffer, 0xFF, BUFFER_SIZE);
		ROM_crc32 = TRIM_crc32;
		for (i = TRIM_size; i < ROM_size; i += BUFFER_SIZE) {
			off_t bytesLeft = ROM_size - i;
			size_t chunk = (BUFFER_SIZE < bytesLeft) ? BUFFER_SIZE : bytesLeft;

			ROM_crc32 = crc32_fast(buffer, chunk, ROM_crc32);
		}
		printf("%08X  %s // trim size: %jd\n", TRIM_crc32, path, (intmax_t)TRIM_size);
		printf("%08X  %s // cart size: %jd\n", ROM_crc32, path, (intmax_t)ROM_size);
		break;

	case md5:
		openssl_hash("md5", fd, TRIM_size, ROM_size, TRIM_md5, ROM_md5);
		fclose(fd);
		printf("File %strimmed\n", FILE_size == TRIM_size ? "" : "not ");
		for (off_t i = 0; i < MD5_DIGEST_LENGTH; i++)
			printf("%.2X", TRIM_md5[i]);
		printf("  %s // trim size: %jd\n", path, (intmax_t)TRIM_size);
		for (off_t i = 0; i < MD5_DIGEST_LENGTH; i++)
			printf("%.2X", ROM_md5[i]);
		printf("  %s // cart size: %jd\n", path, (intmax_t)ROM_size);
		break;

	case sha1:
		openssl_hash("sha1", fd, TRIM_size, ROM_size, TRIM_sha1, ROM_sha1);
		fclose(fd);
		printf("File %strimmed\n", FILE_size == TRIM_size ? "" : "not ");
		for (off_t i = 0; i < SHA_DIGEST_LENGTH; i++)
			printf("%.2X", TRIM_sha1[i]);
		printf("  %s // trim size: %jd\n", path, (intmax_t)TRIM_size);
		for (off_t i = 0; i < SHA_DIGEST_LENGTH; i++)
			printf("%.2X", ROM_sha1[i]);
		printf("  %s // cart size: %jd\n", path, (intmax_t)ROM_size);
		break;
	}
}
#endif

static void usage(void) {
	fprintf(stderr,
		"Usage: xcitools <command> <files...>\n"
		"Commands:\n"
		"c		Calculate CRC32\n"
		"m		Calculate MD5\n"
		"s		Calculate SHA1\n"
		"t		Trims\n"
		"p		Padds\n"
	);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int i;
	enum modes mode;

	if (argc < 2)
		usage();
	
	if (*argv[1] == 't') {
		mode = trim;
	} else if (*argv[1] == 'p') {
		mode = pad;
	} else if (*argv[1] == 'c') {
		mode = crc32;
	} else if (*argv[1] == 'm') {
		mode = md5;
	} else if (*argv[1] == 's') {
		mode = sha1;
	} else {
		usage();
	}

#ifdef WANTS_MMAP
	memset(buffer, 0xFF, BUFFER_SIZE);
#endif

	for (i = 2; i < argc; i++) {
		manage_xci(mode, argv[i]);
	}

	return EXIT_SUCCESS;
}
