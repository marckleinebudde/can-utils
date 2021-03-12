// SPDX-License-Identifier: GPL-2.0
//
// Microchip MCP251xFD Family CAN controller debug tool
//
// Copyright (c) 2020, 2021 Pengutronix,
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

static int sidestep(const struct transfer *orig_transfer)
{
	uint16_t crc_received, crc_calculated;
	struct transfer transfer[1];
	const int steps = 1 << 16;
	int i;

	crc_received = orig_transfer->crc[0] << 8 | orig_transfer->crc[1];

	*transfer = *orig_transfer;

	for (i = -steps; i <= steps; i++) {
		uint32_t data;
		bool ok = false;

		data = le32toh(*(uint32_t *)(orig_transfer->data)) + i;
		*(uint32_t *)(transfer->data) = data;

		crc_calculated = mcp251xfd_crc16_compute2(transfer->cmd, sizeof(transfer->cmd) + sizeof(transfer->len),
							  transfer->data, sizeof(transfer->data));

		if (crc_received == crc_calculated)
			ok = true;

		if (ok) {
			uint8_t xor[4];
			unsigned int w;

			xor[0] = orig_transfer->data[0] ^ transfer->data[0];
			xor[1] = orig_transfer->data[1] ^ transfer->data[1];
			xor[2] = orig_transfer->data[2] ^ transfer->data[2];
			xor[3] = orig_transfer->data[3] ^ transfer->data[3];

			w = hweight8(xor[0]) + hweight8(xor[1]) + hweight8(xor[2]) + hweight8(xor[3]);


			if (w <= 4) {
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
		sidestep(transfer);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct transfer t;
#if 0	
	struct transfer transfers[] = {
#if 0
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x13, 0x7f, 0xba, }, .crc = { 0xe2, 0x36 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x17, 0x82, 0xd4, }, .crc = { 0x6d, 0x07 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x2b, 0x26, 0x38, }, .crc = { 0xb4, 0x55 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x63, 0x99, 0xd6, }, .crc = { 0xb1, 0x98 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x72, 0x37, 0xd3, }, .crc = { 0xd4, 0xdb }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x8b, 0xd4, 0xc1, }, .crc = { 0x12, 0xc6 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0x92, 0xca, 0xdf, }, .crc = { 0x57, 0x7c }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0xa4, 0x77, 0xf8, }, .crc = { 0xda, 0x1c }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0xb2, 0x32, 0x47, }, .crc = { 0x46, 0xa0 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0xba, 0xe0, 0xf6, }, .crc = { 0xa9, 0xaa }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0xd2, 0xd4, 0xa9, }, .crc = { 0x97, 0x41 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0xd8, 0x83, 0xd1, }, .crc = { 0x64, 0xdf }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x00, 0xf5, 0x54, 0xf6, }, .crc = { 0x94, 0x6f }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x04, 0x3b, 0x9c, 0xc1, }, .crc = { 0x7b, 0x03 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x04, 0x8c, 0x7d, 0xa5, }, .crc = { 0x35, 0xfb }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x14, 0x0a, 0x1c, 0x8a, }, .crc = { 0xb9, 0x4a }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x14, 0x53, 0x2b, 0x42, }, .crc = { 0x0d, 0x0e }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x54, 0x91, 0x18, 0x80, }, .crc = { 0x2a, 0xb7 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x54, 0xeb, 0x15, 0xbb, }, .crc = { 0x82, 0x66 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x54, 0xef, 0x08, 0xd2, }, .crc = { 0x4d, 0x43 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x80, 0x96, 0xe8, 0xc8, }, .crc = { 0x9b, 0x54 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x80, 0xd8, 0x74, 0x5b, }, .crc = { 0xd5, 0xec }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x84, 0x0e, 0x58, 0xb2, }, .crc = { 0x61, 0xa2 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x94, 0x06, 0xa6, 0x2d, }, .crc = { 0xa6, 0x49 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0x94, 0x7f, 0xd0, 0x82, }, .crc = { 0x17, 0xda }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xea, 0x00, 0x13, 0xcc, }, .crc = { 0x88, 0x74 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xea, 0x80, 0x00, 0x8d, }, .crc = { 0xe9, 0xf2 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xea, 0x80, 0x67, 0x4a, }, .crc = { 0x39, 0x65 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xeb, 0x00, 0x58, 0xda, }, .crc = { 0xa6, 0x05 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xeb, 0x00, 0xec, 0xa5, }, .crc = { 0x9f, 0x0e }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xeb, 0x00, 0xf2, 0xc2, }, .crc = { 0x5a, 0x5f }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xeb, 0x80, 0x1f, 0xdc, }, .crc = { 0x3e, 0x17 }, },
		{ .cmd = { 0xb0, 0x10, }, .len = 0x4, .data = { 0xeb, 0x80, 0xe9, 0x69, }, .crc = { 0x09, 0xa5 }, },
#endif
		{ .cmd = { 0xb0, 0x1c, }, .len = 0x4, .data = { 0x00, 0x00, 0x1a, 0xbf, }, .crc = { 0x97, 0x7c }, },
		{ .cmd = { 0xb0, 0x1c, }, .len = 0x4, .data = { 0x04, 0x00, 0x1a, 0xbf, }, .crc = { 0x47, 0x7f }, },
		{ .cmd = { 0xb0, 0x1c, }, .len = 0x4, .data = { 0x04, 0x00, 0x1a, 0xbf, }, .crc = { 0xc4, 0x7c }, },		// <-- broken CRC?
	};
#endif

	while (scanf("0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx\n",
			  &t.cmd[0], &t.cmd[1], &t.len,
			  &t.data[0], &t.data[1], &t.data[2], &t.data[3],
			  &t.crc[0], &t.crc[1]) != EOF) {
		t.cmd[0] |= 0xb0;

		analyse_transfer(&t);
	}
	
	exit(EXIT_SUCCESS);
}
