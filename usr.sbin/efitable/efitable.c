/*-
 * Copyright (c) 2021 3mdeb.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <uuid.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/efi.h>
#include <sys/efiio.h>

#define TABLE_MAX_LEN 30
#define ARR_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

static void efi_table_print_esrt(const void *data, int json_format);
static void efi_table_print_prop(const void *data, int json_format);

struct efi_table_op {
	char name[TABLE_MAX_LEN];
	void (*parse) (const void *, int);
	struct uuid uuid; 
};

static struct efi_table_op efi_table_ops[] = {
	{ .name = "esrt", .parse = efi_table_print_esrt, .uuid = EFI_TABLE_ESRT },
	{ .name = "prop", .parse = efi_table_print_prop, .uuid = EFI_PROPERTIES_TABLE }
};

int
main(int argc, char **argv)
{
	struct efi_get_table_ioc table = {
		.buf = NULL,
		.buf_len = 0,
		.table_len = 0
	};

	int efi_fd, ch, rc = 1, efi_idx = -1;
	int got_table = 0;
	int table_set = 0;
	int uuid_set = 0;
	int use_json = 0;

	struct option longopts[] = {
		{ "uuid",  required_argument, NULL, 'u' },
		{ "table", required_argument, NULL, 't' },
		{ "json",  no_argument,       NULL, 'j' },
		{ NULL,    0,                 NULL,  0  }
	};

	while ((ch = getopt_long(argc, argv, "u:t:j", longopts, NULL)) != -1) {
		switch (ch) {
		case 'u':
			{
				char *uuid_str = optarg;
				struct uuid uuid;
				uint32_t status;

				uuid_set = 1;

				uuid_from_string(uuid_str, &uuid, &status);
				if (status != uuid_s_ok) {
					fprintf(stderr, "invalid UUID\n");
					exit(EXIT_FAILURE);
				}
				for (size_t n = 0; n < ARR_LEN(efi_table_ops); n++) {
					if (!memcmp(&uuid, &efi_table_ops[n].uuid, sizeof(uuid))) {
						efi_idx = n;
						got_table = 1;
						break;
					}
				}
                break;
            }
		case 't':
			{
				char *table_name = optarg;

				table_set = 1;

				for (size_t n = 0; n < ARR_LEN(efi_table_ops); n++) {
					if (!strcmp(table_name, efi_table_ops[n].name)) {
						efi_idx = n;
						got_table = 1;
						break;
					}
				}

				if (!got_table) {
					fprintf(stderr, "unsupported efi table\n");
					exit(EXIT_FAILURE);
				}

				break;
			}
		case 'j':
			use_json = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-d uuid | -t name] [-j]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!table_set && !uuid_set) {
		fprintf(stderr, "table is not set\n");
		exit(EXIT_FAILURE);
	}

	if (!got_table) {
		fprintf(stderr, "unsupported table\n");
		exit(EXIT_FAILURE);
	}

	efi_fd = open("/dev/efi", O_RDWR);
	if (efi_fd < 0) {
		fprintf(stderr, "Cannot open /dev/efi: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	table.uuid = efi_table_ops[efi_idx].uuid;
	if (ioctl(efi_fd, EFIIOC_GET_TABLE, &table) == -1) {
		fprintf(stderr, "0:ioctl error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("Got table len: %zu\n", table.table_len);
    table.buf = malloc(table.table_len);
	table.buf_len = table.table_len;

	if (ioctl(efi_fd, EFIIOC_GET_TABLE, &table) == -1) {
		fprintf(stderr, "1:ioctl error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	efi_table_ops[efi_idx].parse(table.buf, use_json);
	close(efi_fd);

	return (rc);
}

static void efi_table_print_esrt(const void *data, int json_format)
{
	const struct efi_esrt_table *esrt = NULL;
	const struct efi_esrt_entry_v1 *entries_v1;

	esrt = (const struct efi_esrt_table *)data;
	if (!json_format) {
		printf("fw_resource_count: %u\n", esrt->fw_resource_count);
		printf("fw_resource_count_max: %u\n", esrt->fw_resource_count_max);
		printf("fw_resource_version: %lu\n", esrt->fw_resource_version);

		entries_v1 = (const void *) esrt->entries;
		for (uint32_t i = 0; i < esrt->fw_resource_count; i++) {
			const struct efi_esrt_entry_v1 *e = &entries_v1[i];
			uint32_t status;
			char *uuid;

			uuid_to_string(&e->fw_class, &uuid, &status);
			if (status != uuid_s_ok) {
				fprintf(stderr, "uuid_to_string error\n");
				exit(EXIT_FAILURE);
			}

			printf("%s%d:\n", "entry", i);
			printf("  %s: %s\n", "fw_class", uuid);
			printf("  %s: %u\n", "fw_type", e->fw_type);
			printf("  %s: %u\n", "fw_version", e->fw_version);
			printf("  %s: %u\n", "lowest_supported_fw_version",
					e->lowest_supported_fw_version);
			printf("  %s: %#x\n", "capsule_flags", e->capsule_flags);
			printf("  %s: %u\n", "last_attempt_version", e->last_attempt_version);
			printf("  %s: %u\n", "last_attempt_status", e->last_attempt_status);

			free(uuid);

			return;
		}
	}

	printf("{");
	printf("\"fw_resource_count\": \"%u\",", esrt->fw_resource_count);
	printf("\"fw_resource_count_max\": \"%u\",", esrt->fw_resource_count_max);
	printf("\"fw_resource_version\": \"%lu\",", esrt->fw_resource_version);
	printf("\"entries\":[");

	entries_v1 = (const void *) esrt->entries;
	for (uint32_t i = 0; i < esrt->fw_resource_count; i++) {
		const struct efi_esrt_entry_v1 *e = &entries_v1[i];
		uint32_t status;
		char *uuid;

		uuid_to_string(&e->fw_class, &uuid, &status);
		if (status != uuid_s_ok) {
			fprintf(stderr, "\nuuid_to_string error\n");
			exit(EXIT_FAILURE);
		}

		printf("%s", (!i) ? "{" : ",{");
		printf("\"%s\": \"%s\",", "fw_class", uuid);
		printf("\"%s\": \"%u\",", "fw_type", e->fw_type);
		printf("\"%s\": \"%u\",", "fw_version", e->fw_version);
		printf("\"%s\": \"%u\",", "lowest_supported_fw_version",
				e->lowest_supported_fw_version);
		printf("\"%s\": \"%#x\",", "capsule_flags", e->capsule_flags);
		printf("\"%s\": \"%u\",", "last_attempt_version", e->last_attempt_version);
		printf("\"%s\": \"%u\"", "last_attempt_status", e->last_attempt_status);
		printf("%s", "}");

		free(uuid);
	}
	printf("]}");

	return;
}

static void efi_table_print_prop(const void *data, int json_format)
{
	const struct efi_prop_table *prop = NULL;

	prop = (const struct efi_prop_table *)data;

	if (!json_format) {
		printf("version: %#x\n", prop->version);
		printf("length: %u\n", prop->length);
		printf("memory_protection_attribute: %#lx\n",
				prop->memory_protection_attribute);
		return;
	}

	printf("{");
	printf("\"version\": \"%#x\",", prop->version);
	printf("\"length\": \"%u\",", prop->length);
	printf("\"memory_protection_attribute\": \"%#lx\"",
			prop->memory_protection_attribute);
	printf("}");

	return;
}

#if 0
	printf("Got ESRT table phys address: %p\n\n", table.ptr);
	mem_fd = open("/dev/mem", O_RDONLY, 0);
	if (efi_fd < 0) {
		fprintf(stderr, "Cannot open /dev/mem: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	memp = mmap(NULL, 4096, PROT_READ, MAP_SHARED, mem_fd, (uint64_t)table.ptr);
	if (memp == MAP_FAILED) {
		fprintf(stderr, "Cannot map /dev/mem: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif
