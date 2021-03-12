// SPDX-License-Identifier: GPL-2.0
//
// Microchip MCP251xFD Family CAN controller debug tool
//
// Copyright (c) 2020, 2021, 2022 Pengutronix,
//               Marc Kleine-Budde <kernel@pengutronix.de>
//

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include <linux/kernel.h>

#include "mcp251xfd.h"

#define __const_hweight8(w)             \
        ((unsigned int)                 \
         ((!!((w) & (1ULL << 0))) +     \
          (!!((w) & (1ULL << 1))) +     \
          (!!((w) & (1ULL << 2))) +     \
          (!!((w) & (1ULL << 3))) +     \
          (!!((w) & (1ULL << 4))) +     \
          (!!((w) & (1ULL << 5))) +     \
          (!!((w) & (1ULL << 6))) +     \
          (!!((w) & (1ULL << 7)))))

#define __const_hweight16(w) (__const_hweight8(w)  + __const_hweight8((w)  >> 8 ))
#define __const_hweight32(w) (__const_hweight16(w) + __const_hweight16((w) >> 16))
#define __const_hweight64(w) (__const_hweight32(w) + __const_hweight32((w) >> 32))

#define hweight8(w) __const_hweight8(w)

struct __attribute__((packed)) transfer {
	uint8_t cmd[2];
	uint8_t len;
	uint8_t data[4];
	uint8_t crc[2];
};

static int bitflip(const struct transfer *orig_transfer, unsigned int width)
{
	uint16_t crc_received, crc_calculated;
	struct transfer transfer[1];
	const u64 steps = (1UL << width) - 1;
	u64 i;

	crc_received = orig_transfer->crc[0] << 8 | orig_transfer->crc[1];

	*transfer = *orig_transfer;

	for (i = 0; i <= steps; i++) {
		uint32_t data;

		data = le32toh(*(uint32_t *)(orig_transfer->data)) ^ i;
		*(uint32_t *)(transfer->data) = data;

		crc_calculated = mcp251xfd_crc16_compute2(transfer->cmd, sizeof(transfer->cmd) + sizeof(transfer->len),
							  transfer->data, sizeof(transfer->data));

		if (crc_received == crc_calculated) {
			uint8_t xor[4];
			unsigned int w;

			xor[0] = orig_transfer->data[0] ^ transfer->data[0];
			xor[1] = orig_transfer->data[1] ^ transfer->data[1];
			xor[2] = orig_transfer->data[2] ^ transfer->data[2];
			xor[3] = orig_transfer->data[3] ^ transfer->data[3];

			w = hweight8(xor[0]) + hweight8(xor[1]) + hweight8(xor[2]) + hweight8(xor[3]);


			if (w <= 2) {
				printf("                                                     data=%02x %02x %02x %02x\t--> FIXED\n",
				       transfer->data[0], transfer->data[1], transfer->data[2], transfer->data[3]);
				printf("                                              xor'ed data=%02x %02x %02x %02x\t--> %d bitflip(s)\n",
				       xor[0], xor[1], xor[2], xor[3], w);
			}
		}
	}

	return 0;
}

static void analyse_transfer(struct transfer *transfer)
{
	uint16_t crc_received, crc_calculated;
	bool ok = false;

	crc_received = transfer->crc[0] << 8 | transfer->crc[1];
	crc_calculated = mcp251xfd_crc16_compute2(transfer->cmd, sizeof(transfer->cmd) + sizeof(transfer->len),
						  transfer->data, sizeof(transfer->data));

	if (crc_received == crc_calculated)
		ok = true;

	if (ok) {
		printf("reg=0x%02x%02x crc_received=0x%04x crc_calculated=0x%04x\t-->OK\n",
		       transfer->cmd[0] & 0x0f, transfer->cmd[1],
		       crc_received, crc_calculated);
	} else {
		printf("reg=0x%02x%02x crc_received=0x%04x crc_calculated=0x%04x data=%02x %02x %02x %02x\t--> BAD\n",
		       transfer->cmd[0] & 0x0f, transfer->cmd[1],
		       crc_received, crc_calculated,
		       transfer->data[0], transfer->data[1], transfer->data[2], transfer->data[3]);
		bitflip(transfer, 32);
	}
	printf("------------------------------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
	struct transfer t;

	while (scanf("0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx\n",
			  &t.cmd[0], &t.cmd[1], &t.len,
			  &t.data[0], &t.data[1], &t.data[2], &t.data[3],
			  &t.crc[0], &t.crc[1]) != EOF) {
		t.cmd[0] |= 0xb0;

		analyse_transfer(&t);
	}

	exit(EXIT_SUCCESS);
}
