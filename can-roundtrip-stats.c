/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/* Copyright (c) 2022 Vincent Mailhol <mailhol.vincent@wanadoo.fr> */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>

#include <time.h>

#include <byteswap.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/select.h>

#include <limits.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#define debug(debug_level, fmt, args...)		\
({							\
	if (DEBUG >= debug_level)			\
		printf("%s:%d:%s(): " fmt, __FILE__,	\
		       __LINE__, __func__, ##args);	\
 })

#define debug_no_header(debug_level, fmt, args...)	\
({							\
	if (DEBUG >= debug_level)			\
		printf(fmt, ##args);			\
})

#define error(fmt, args...)				\
({							\
	fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__,	\
		__LINE__, __func__, ##args);		\
})

/* Comment out this line to deactivate Hardware timestamps */
#define HARDWARE_TIMESTAMP

static inline struct timespec
timespec_sub(const struct timespec a, const struct timespec b)
{
	struct timespec diff;

	diff.tv_sec = a.tv_sec - b.tv_sec;
	diff.tv_nsec = a.tv_nsec - b.tv_nsec;
	if (diff.tv_nsec < 0) {
		diff.tv_sec--;
		diff.tv_nsec += 1000000000;
	}
	if (diff.tv_sec < 0)
		memset(&diff, 0, sizeof(diff));

	return diff;
}

/* Convert ascii hexadecimal value to int. */
static int nibble_to_int(char hex)
{
	if (!isxdigit(hex)) {
		error("Expected ascii hexadecimal value but got %c (0x%x).\n", hex, hex);
		exit(EXIT_FAILURE);
	}

	switch (hex) {

	case '0': return 0x0;
	case '1': return 0x1;
	case '2': return 0x2;
	case '3': return 0x3;
	case '4': return 0x4;
	case '5': return 0x5;
	case '6': return 0x6;
	case '7': return 0x7;
	case '8': return 0x8;
	case '9': return 0x9;
	case 'a': case 'A': return 0xa;
	case 'b': case 'B': return 0xb;
	case 'c': case 'C': return 0xc;
	case 'd': case 'D': return 0xd;
	case 'e': case 'E': return 0xe;
	case 'f': case 'F': return 0xf;

	default:
		error("This portion of code should not be reached.\n");
		exit(EXIT_FAILURE);
	}
}

/* Convert the first two hexadecimal charater of the string to an int. */
static uint8_t byte_to_int(char *hex)
{
	uint8_t res;

	res = nibble_to_int(hex[0]);
	res <<= 4;
	res += nibble_to_int(hex[1]);

	return res;
}

/* Convert the 64 bits (8 bytes) payload into an integer. */
static uint64_t data_to_int(uint8_t *data)
{
	uint64_t res;

	res = (uint64_t)data[0] << 56;
	res += (uint64_t)data[1] << 48;
	res += (uint64_t)data[2] << 40;
	res += (uint64_t)data[3] << 32;
	res += (uint64_t)data[4] << 24;
	res += (uint64_t)data[5] << 16;
	res += (uint64_t)data[6] << 8;
	res += (uint64_t)data[7];

	return res;
}

static void make_can_frame(struct can_frame *frame, int can_id, char *data)
{
	size_t data_length;
	size_t can_dlc;
	size_t i;

	data_length = strlen(data);
	if (data_length % 2 == 1)
		error("Payload contains some half bytes.\n");

	can_dlc = data_length / 2;
	if (can_dlc > CAN_MAX_DLEN)
		error("Maximum payload length is 8 bytes.\n");

	frame->can_id = can_id;
	frame->can_dlc = can_dlc;

	for (i = 0; i < can_dlc; i++)
		frame->data[i] = byte_to_int(data + 2 * i);
}

static void make_canfd_frame(struct canfd_frame *frame, int can_id, char *data, uint8_t flags)
{
	size_t data_length;
	size_t can_len;
	size_t i;

	data_length = strlen(data);
	if (data_length % 2 == 1)
		error("Payload contains some half bytes.\n");

	can_len = data_length / 2;
	if (can_len > CANFD_MAX_DLEN)
		error("Maximum payload length is 8 bytes.\n");

	frame->can_id = can_id;
	frame->len = can_len;
	frame->flags = flags;

	for (i = 0; i < can_len; i++)
		frame->data[i] = byte_to_int(data + 2 * i);
}

static void send_can_frame(int soc, int can_id, size_t len, uint64_t data)
{
	struct can_frame frame;
	ssize_t sentbytes;

	frame.can_id = can_id;
	frame.can_dlc = (len > 8 ? 8 : len);
	memcpy(frame.data, &data, frame.can_dlc);
	sentbytes = write(soc, &frame, sizeof(struct can_frame));

	if (sentbytes != sizeof(struct can_frame))
		debug(1, "Wrote %zd bytes instead of %zd.\n",
		      sentbytes, sizeof(struct can_frame));
	else
		debug(2, "Wrote %zd bytes.\n", sentbytes);

	debug(1, "Send: %03X [%d] %0*" PRIX64 ".\n",
	      frame.can_id, frame.can_dlc, frame.can_dlc * 2, data_to_int(frame.data));
}

static void send_can_frame_str(int soc, int can_id, char *data)
{
	struct can_frame frame;
	ssize_t sentbytes;

	make_can_frame(&frame, can_id, data);
	sentbytes = write(soc, &frame, sizeof(frame));

	if (sentbytes != sizeof(frame))
		debug(1, "Wrote %zd bytes instead of %zd.\n",
		      sentbytes, sizeof(struct can_frame));
	else
		debug(2, "Wrote %zd bytes.\n", sentbytes);

	debug(1, "Send: %03X [%d] %0*" PRIX64 ".\n",
	      frame.can_id, frame.can_dlc, frame.can_dlc * 2,
	      data_to_int(frame.data));
}

static void send_canfd_frame_str(int soc, int can_id, char *data, uint8_t flags)
{
	struct canfd_frame frame;
	ssize_t sentbytes;

	make_canfd_frame(&frame, can_id, data, flags);
	sentbytes = write(soc, &frame, sizeof(frame));

	if (sentbytes != sizeof(frame))
		debug(1, "Wrote %zd bytes instead of %zd.\n",
		      sentbytes, sizeof(struct can_frame));
	else
		debug(2, "Wrote %zd bytes.\n", sentbytes);

	debug(1, "Send: %03X [%d] %0*" PRIX64 ".\n",
	      frame.can_id, frame.len, frame.len * 2,
	      data_to_int(frame.data));
}

static int read_can_frame(int soc, struct can_frame *frame, int ms_timeout)
{
	int recvbytes = 0;
	fd_set readSet;
	struct timeval timeout = {
		.tv_sec = ms_timeout / 1000,
		.tv_usec =(ms_timeout % 1000) * 1000,
	};

	FD_ZERO(&readSet);
	FD_SET(soc, &readSet);

	if (select(soc + 1, &readSet, NULL, NULL, &timeout) >= 0) {
		if (FD_ISSET(soc, &readSet)) {
			int i;

			recvbytes = read(soc, frame, sizeof(*frame));
			if (!recvbytes)
				error("This portion of code should not be reached.\n");

			debug(1, "Receive: %03X [%d] ",
			      frame->can_id, frame->len);
			for (i = 0; i < frame->len; i++)
				debug_no_header(1, "%02X", frame->data[i]);
			debug_no_header(1, ".\n");
			return 1;
		} else {
			debug(3, "Select timed out.\n");
			return 0;
		}
	} else {
		perror("Select error");
	}

	return -1;
}

static bool is_timestamp_zero(struct timespec ts)
{
	return !(ts.tv_sec || ts.tv_nsec);
}

enum timestamp_type {
	NONE = 0x00,
	SW = 0x01,
	HW = 0x02
};

static enum timestamp_type get_timestamp_type(struct timespec *sw_ts, struct timespec *hw_ts)
{
	enum timestamp_type type = NONE;

	if (!is_timestamp_zero(*sw_ts))
		type |= SW;
	if (!is_timestamp_zero(*hw_ts))
		type |= HW;


	return type;
}

static enum timestamp_type get_tx_timestamp(int soc, struct msghdr *msg,
					    struct timespec *sw_ts, struct timespec *hw_ts)
{
	struct cmsghdr *cmsg;
	int i, ret;

	ret = recvmsg(soc, msg, MSG_ERRQUEUE | 0);
	if (ret <= 0) {
		perror("get_tx_timestamp:recvmsg");
		return ret;
	} else {
		struct canfd_frame *frame = msg->msg_iov->iov_base;
		debug(1, "Receive (errqueue): %03X [%d], data: %" PRIu64 "\n",
		      frame->can_id, frame->len, data_to_int(frame->data));
	}

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg /* && (cmsg->cmsg_level == SOL_SOCKET) */;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		struct scm_timestamping *tss;
		struct sock_extended_err *serr;

		switch (cmsg->cmsg_type) {
		case SCM_TIMESTAMPING:
			tss = (struct scm_timestamping *)CMSG_DATA(cmsg);
			for (i = 0;
			     i < (int)(cmsg->cmsg_len / sizeof(*tss->ts));
			     i++)
				debug(1, "SCM_TIMESTAMPING: tss->ts[%d]: %lu.%lu\n",
				      i, tss->ts[i].tv_sec, tss->ts[i].tv_nsec);
			if (!is_timestamp_zero(tss->ts[0]))
				*sw_ts = tss->ts[0];
			if (!is_timestamp_zero(tss->ts[2]))
				*hw_ts = tss->ts[2];
			break;

		case PACKET_TX_TIMESTAMP:
			serr = (struct sock_extended_err *)CMSG_DATA(cmsg);
			if (serr->ee_errno != ENOMSG ||
			    serr->ee_origin != SO_EE_ORIGIN_TIMESTAMPING) {
				fprintf(stderr, "unknown ip error %d %d\n",
					serr->ee_errno,
					serr->ee_origin);
				serr = NULL;
			} else {
				debug(1, "PACKET_TX_TIMESTAMP: ee_info: %d, ee_data: %d\n",
				      serr->ee_info, serr->ee_data);
			}
			break;

		default:
			debug(1, "Unknown cmsg_type: %d\n", cmsg->cmsg_type);
		}
	}

	return get_timestamp_type(sw_ts, hw_ts);
}

static enum timestamp_type get_rx_timestamp(int soc, struct msghdr *msg,
					    struct timespec *sw_ts, struct timespec *hw_ts)
{
	struct cmsghdr *cmsg;
	int i, ret;

	ret = recvmsg(soc, msg, 0);
	if (ret <= 0) {
		perror("get_rx_timestamp:recvmsg");
		return ret;
	} else {
		struct canfd_frame *frame = msg->msg_iov->iov_base;
		debug(1, "Receive (errqueue): %03X [%d], data: %" PRIu64 "\n",
		      frame->can_id, frame->len, data_to_int(frame->data));
	}

	if (!(msg->msg_flags & MSG_DONTROUTE)) {
		debug(0, "We are not the sender, ignore the frame");
		return -ENODATA;
	}

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg /* && (cmsg->cmsg_level == SOL_SOCKET) */;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		struct timeval *tv;
		struct timespec *stamp;

		switch (cmsg->cmsg_type) {
		case SO_TIMESTAMP:
			tv = (struct timeval *)CMSG_DATA(cmsg);
			debug(1, "SO_TIMESTAMP: stamp = %lu.%06lu\n",
			      tv->tv_sec, tv->tv_usec);
			sw_ts->tv_sec = tv->tv_sec;
			sw_ts->tv_nsec = tv->tv_usec * 1000;
			break;

		case SO_TIMESTAMPING:
			stamp = (struct timespec *)CMSG_DATA(cmsg);
			for (i = 0;
			     i < (int)(cmsg->cmsg_len / sizeof(*stamp));
			     i++)
				debug(1, "SO_TIMESTAMPING: stamp[%d] = %ld.%09ld\n",
				      i, stamp[i].tv_sec, stamp[i].tv_nsec);
			*sw_ts = stamp[0];
			*hw_ts = stamp[2];
			break;

		default:
			debug(1, "Unknown cmsg_type: %d\n", cmsg->cmsg_type);
		}
	}

	return get_timestamp_type(sw_ts, hw_ts);
}

static void print_stats(const char *timestamp_name, canid_t canid,
			struct timespec tx, struct timespec rx, struct timespec diff)
{
	printf("[%s] ID: 0x%03x, TX: %10ld.%09ld, RX: %10ld.%09ld, diff: %ld.%09ld\n",
	       timestamp_name, canid,
	       tx.tv_sec, tx.tv_nsec,
	       rx.tv_sec, rx.tv_nsec,
	       diff.tv_sec, diff.tv_nsec);

}

static void calc_and_print_stats(struct timespec user_tx, struct timespec user_rx,
				 struct timespec kernel_sw_tx, struct timespec kernel_sw_rx,
				 struct timespec kernel_hw_tx, struct timespec kernel_hw_rx,
				 int drop_cnt, canid_t canid)
{
	struct timespec kernel_sw_diff, kernel_hw_diff, user_diff;
	struct timespec user_to_kernel_tx, kernel_to_user_rx;
	static double kernel_time_sum = 0, user_time_sum = 0;
	static double user_to_kernel_tx_sum = 0, kernel_to_user_rx_sum = 0;

	static int cnt = 0;

	kernel_sw_diff = timespec_sub(kernel_sw_rx, kernel_sw_tx);
	kernel_hw_diff = timespec_sub(kernel_hw_rx, kernel_hw_tx);
	kernel_time_sum += kernel_sw_diff.tv_sec + kernel_sw_diff.tv_nsec / 1000000000.;
	user_to_kernel_tx = timespec_sub(kernel_sw_tx, user_tx);
	user_to_kernel_tx_sum += user_to_kernel_tx.tv_sec + user_to_kernel_tx.tv_nsec / 1000000000.;
	kernel_to_user_rx = timespec_sub(user_rx, kernel_sw_rx);
	kernel_to_user_rx_sum += kernel_to_user_rx.tv_sec + kernel_to_user_rx.tv_nsec / 1000000000.;
	user_diff = timespec_sub(user_rx, user_tx);
	user_time_sum += user_diff.tv_sec + user_diff.tv_nsec / 1000000000.;
	cnt++;

	print_stats("User           ", canid, user_tx, user_rx, user_diff);
	print_stats("Kernel Software", canid, kernel_sw_tx, kernel_sw_rx, kernel_sw_diff);
	if (!(is_timestamp_zero(kernel_hw_tx) || is_timestamp_zero(kernel_hw_rx)))
		print_stats("Kernel Hardware", canid, kernel_hw_tx, kernel_hw_rx, kernel_hw_diff);
	printf("User to kernel TX: %ld.%09ld, kernel to user RX: %ld.%09ld\n",
	       timespec_sub(kernel_sw_tx, user_tx).tv_sec,
	       timespec_sub(kernel_sw_tx, user_tx).tv_nsec,
	       timespec_sub(user_rx, kernel_sw_rx).tv_sec,
	       timespec_sub(user_rx, kernel_sw_rx).tv_nsec);
	printf("[Average] Total: %4d, drop count: %3d, user to kernel (tx): %fs, kernel round trip: %fs, kernel to user (rx): %fs, user round trip: %fs\n\n",
	       cnt, drop_cnt,
	       user_to_kernel_tx_sum / cnt,
	       kernel_time_sum / cnt, kernel_to_user_rx_sum / cnt,
	       user_time_sum / cnt);
}

int main(int argc, char **argv)
{
	int soc;
	struct sockaddr_can addr = { 0 };
	struct ifreq ifr = { 0 };

	const char *default_ifname = "can0";
	const char *ifname;
	const int canfd_on = 1;

	struct iovec iov;
	struct msghdr msg;
	char ctrlmsg[CMSG_SPACE(sizeof(struct timeval) +
				3 * sizeof(struct timespec) +
				sizeof(__u32))];
	const int recv_own_msg = 1;
	const int timestamping_flags_sw = SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE;

#ifdef HARDWARE_TIMESTAMP
	const int timestamping_flags_hw = SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE |
		SOF_TIMESTAMPING_OPT_TX_SWHW;

	const int timestamping_flags = timestamping_flags_sw | timestamping_flags_hw;
#else
	const int timestamping_flags = timestamping_flags_sw;
#endif

	struct canfd_frame frame;
	int can_id = 0 /* | CAN_EFF_FLAG */;

	struct timespec kernel_sw_tx = { }, kernel_sw_rx = { };
	struct timespec kernel_hw_tx = { }, kernel_hw_rx = { };
	struct timespec user_tx, user_rx;

	if (argc != 2)
		ifname = default_ifname;
	else
		ifname = argv[1];

	if ((soc = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("Error while opening CAN socket");
		exit(EXIT_FAILURE);
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ioctl(soc, SIOCGIFINDEX, &ifr);

	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	/* try to switch the socket into CAN FD mode */
	setsockopt(soc, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &canfd_on, sizeof(canfd_on));
	setsockopt(soc, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &recv_own_msg, sizeof(recv_own_msg));

	if (setsockopt(soc, SOL_SOCKET, SO_TIMESTAMPING,
		       &timestamping_flags, sizeof(timestamping_flags)) < 0) {
		perror("setsockopt SO_TIMESTAMPING is not supported by your Linux kernel");
		return EXIT_FAILURE;
	}

	printf("%s at index %d\n", ifname, ifr.ifr_ifindex);

	if (bind(soc, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Error in socket bind");
		exit(EXIT_FAILURE);
	}

	frame.can_id = 0;
	/* these settings are static and can be held out of the hot path */
	iov.iov_base = &frame;
	msg.msg_name = &addr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrlmsg;

	while (true) {
		static int drop_cnt = 0;
		enum timestamp_type tx_type = NONE, rx_type = NONE;
		int ret;

		/* these settings may be modified by recvmsg() */
		iov.iov_len = sizeof(frame);
		msg.msg_namelen = sizeof(addr);
		msg.msg_controllen = sizeof(ctrlmsg);
		msg.msg_flags = 0;

		/* send new frame */
		usleep(100000);
		clock_gettime(CLOCK_REALTIME, &user_tx);
		send_canfd_frame_str(soc, can_id++, "", CANFD_BRS);

		/*
		 * Reading from the error queue is always a
		 * non-blocking operation. c.f.:
		 * https://docs.kernel.org/networking/timestamping.html#blocking-read
		 * Read first from the "normal" queue to leave time
		 * for the error queue to be ready
		 */
		rx_type |= get_rx_timestamp(soc, &msg, &kernel_sw_rx, &kernel_hw_rx);

		/*
		 * Empirical tests show that the error queue is always
		 * ready after the "normal" one. This while loop is
		 * just a failsafe.
		 * Yet, TODO: use poll() or select() instead of this
		 * dirty while loop.
		 */
		while ((ret = get_tx_timestamp(soc, &msg, &kernel_sw_tx, &kernel_hw_tx)) < 0);
		tx_type |= ret;

		if (timestamping_flags & SOF_TIMESTAMPING_OPT_TX_SWHW) {
			/*
			 * Need to unqueue the error queue twice: once for
			 * software and once for hardware timesptamps
			 */
			while ((ret = get_tx_timestamp(soc, &msg, &kernel_sw_tx, &kernel_hw_tx)) < 0);
			tx_type |= ret;
		}

		/*
		 * Assert that we got at least the software timestamp
		 * for TX and RX
		 */
		if (!(rx_type & tx_type & SW)) {
			drop_cnt++;
			continue;
		}

		clock_gettime(CLOCK_REALTIME, &user_rx);
		calc_and_print_stats(user_tx, user_rx,
				     kernel_sw_tx, kernel_sw_rx,
				     kernel_hw_tx, kernel_hw_rx, drop_cnt,
				     ((struct canfd_frame *)msg.msg_iov->iov_base)->can_id);
	}

	close(soc);

	return EXIT_SUCCESS;
}
