/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * Author: Alexandre Bailon <abailon@baylibre.com>
 * Copyright (c) 2016 Alexandre Bailon
 */

#include <debug.h>
#include <gbridge.h>
#include <controller.h>
#include <controllers/uart.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <endian.h>

void dump_msg(const char *func, struct gb_operation_msg_hdr *msg) {

	unsigned msg_size = le16toh(msg->size);
	unsigned msg_id = le16toh(msg->operation_id);
	unsigned cport = (((unsigned)msg->pad[1]) << 8) | msg->pad[0];
	unsigned payload_size = msg_size - 8;
	uint8_t *byte;

	pr_err(
		"%s(): "
		"size: %u, "
		"id: %u, "
		"type: %02x, "
		"result: %u, "
		"cport: %u, "
		,
		func,
		msg_size,
		msg_id,
		msg->type,
		msg->result,
		cport
	);
	if (payload_size > 0) {
		pr_err("payload: ");
		byte = (uint8_t *)msg + sizeof(*msg);
		for(size_t i = 0; i < payload_size; i++, byte++) {
			pr_err("%02x ", (unsigned)(*byte));
		}
	}
	pr_err("\n");
}

struct controller uart_controller;

struct uart_controller {
	int fd;
};

int register_uart_controller(const char *file_name, int baudrate)
{
	int ret;
	struct termios tio;
	struct controller *ctrl;
	struct uart_controller *uart_ctrl;

	uart_ctrl = malloc(sizeof(*uart_ctrl));
	if (!uart_ctrl)
		return -ENOMEM;

	tcgetattr(uart_ctrl->fd, &tio);
	cfsetospeed(&tio, baudrate);
	cfsetispeed(&tio, baudrate);
	tio.c_cflag = CS8 | CREAD;
	tio.c_iflag = IGNBRK;
	tio.c_lflag = 0;
	tio.c_oflag = 0;
	tio.c_cc[VMIN] = 1; // 1 character minimum
	tio.c_cc[VTIME] = 1; // 100ms timeout

	uart_ctrl->fd = open(file_name, O_RDWR | O_NOCTTY);
	if (uart_ctrl->fd < 0) {
		free(uart_ctrl);
		return uart_ctrl->fd;
	}

	ret = tcsetattr(uart_ctrl->fd, TCSANOW, &tio);
	if (ret < 0) {
		close(uart_ctrl->fd);
		free(uart_ctrl);
	}

	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl) {
		close(uart_ctrl->fd);
		free(uart_ctrl);
		return -ENOMEM;
	}

	memcpy(ctrl, &uart_controller, sizeof(*ctrl));
	ctrl->priv = uart_ctrl;
	register_controller(ctrl);

	return 0;
}

static int uart_init(struct controller * ctrl)
{
	return 0;
}

static void uart_exit(struct controller * ctrl)
{
	struct uart_controller *uart_ctrl = ctrl->priv;

	close(uart_ctrl->fd);
	free(uart_ctrl);
}

static int uart_hotplug(struct controller *ctrl)
{
	int ret;
	struct interface *intf;

	/* FIXME: use real IDs */
	intf = interface_create(ctrl, 1, 1, 0x1234, NULL);
	if (!intf)
		return -ENOMEM;

	ret = interface_hotplug(intf);
	if (ret < 0) {
		interface_destroy(intf);
		return ret;
	}

	return 0;
}

static int uart_write(struct connection * conn, void *data, size_t len)
{
	struct uart_controller *ctrl = conn->intf2->ctrl->priv;

	cport_pack(data, conn->cport2_id);

	dump_msg(__func__, data);

	return write(ctrl->fd, data, len);
}

static int _uart_read(struct uart_controller *ctrl,
		      void *data, size_t len)
{
	int ret;
	size_t remaining;
	size_t offset;
	size_t recvd;

	if (0 == len) {
		return 0;
	}

	for(remaining = len, offset = 0, recvd = 0; remaining; remaining -= recvd, offset += recvd, recvd = 0) {
		ret = read(ctrl->fd, &((uint8_t *)data)[offset], remaining);
		if (-1 == ret) {
			if (EAGAIN == errno) {
				continue;
			}
			ret = -errno;
			pr_err("%s(): read: %s\n", __func__, strerror(errno));
			return ret;
		}
		recvd = ret;
	}

	return 0;
}

static int uart_read(struct interface * intf,
		     uint16_t * cport_id, void *data, size_t len)
{
	int ret;
	uint8_t *p_data = data;
	struct uart_controller *ctrl = intf->ctrl->priv;

	ret = _uart_read(ctrl, p_data, sizeof(struct gb_operation_msg_hdr));
	if (ret) {
		pr_err("Failed to get header\n");
		return ret;
	}

	ret = gb_operation_msg_size(data);
	if (ret > len) {
		pr_err("Message to big\n");
		return -EMSGSIZE;	/* FIXME: drop remaining data */
	}

	p_data += sizeof(struct gb_operation_msg_hdr);
	len = ret - sizeof(struct gb_operation_msg_hdr);
	ret = _uart_read(ctrl, p_data, len);
	if (ret) {
		pr_err("Failed to get the payload\n");
		return ret;
	}

	dump_msg(__func__, data);

	*cport_id = cport_unpack(data);

	return len + sizeof(struct gb_operation_msg_hdr);
}

struct controller uart_controller = {
	.name = "uart",
	.init = uart_init,
	.exit = uart_exit,
	.write = uart_write,
	.intf_read = uart_read,
	.event_loop = uart_hotplug,
};
