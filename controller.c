/*
 * GBridge (Greybus Bridge)
 * Copyright (c) 2016 Alexandre Bailon
 *
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
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <debug.h>
#include <gbridge.h>
#include <controller.h>

static
TAILQ_HEAD(conn_head, connection)
connections = TAILQ_HEAD_INITIALIZER(connections);
static
TAILQ_HEAD(ctrl_head, controller)
controllers = TAILQ_HEAD_INITIALIZER(controllers);
static uint8_t g_intf_id = 0;
static pthread_mutex_t intf_alloc_lock;

void cport_pack(struct gb_operation_msg_hdr *header, uint16_t cport_id)
{
	header->pad[0] = cport_id;
}

uint16_t cport_unpack(struct gb_operation_msg_hdr *header)
{
	return (uint16_t) header->pad[0];
}

void cport_clear(struct gb_operation_msg_hdr *header)
{
	header->pad[0] = 0;
}

static int _read(int fd, void *data, size_t len)
{
	int ret;
	uint8_t *pdata = data;

	do {
		ret = read(fd, pdata, len);
		if (ret < 0) {
			pr_err("Failed to read header\n");
			return ret;
		}
		pdata += ret;
		len -= ret;
	}
	while (len);

	return 0;
}

int read_gb_msg(int fd, void *data, size_t max_len)
{
	int ret;
	uint8_t *pdata = data;
	size_t len = sizeof(struct gb_operation_msg_hdr);

	ret = _read(fd, pdata, len);
	if (ret < 0)
		return ret;

	pdata += len;
	pr_dump(data, 8);
	len = gb_operation_msg_size(data);
	if (len > max_len)
		return -EMSGSIZE;
	len -= sizeof(struct gb_operation_msg_hdr);

	ret = _read(fd, pdata, len);
	if (ret < 0)
		return ret;

	return gb_operation_msg_size(data);
}

int hd_to_intf_cport_id(uint16_t hd_cport_id,
			uint8_t *intf_id, uint16_t *cport_id)
{
	struct connection *conn;

	if (hd_cport_id == SVC_CPORT) {
		*intf_id = 0;
		*cport_id = 0;
		return 0;
	}

	TAILQ_FOREACH(conn, &connections, node) {
		if (conn->cport1_id == hd_cport_id) {
			*intf_id = conn->intf2->id;
			*cport_id = conn->cport2_id;
			return 0;
		}
	}

	return -EINVAL;
}

static struct connection *_get_connection(struct interface *intf,
					  uint16_t cport_id)
{
	struct connection *conn;

	TAILQ_FOREACH(conn, &connections, node) {
		if (conn->intf1 == intf && conn->cport1_id == cport_id)
			return conn;
		if (conn->intf2 == intf && conn->cport2_id == cport_id)
			return conn;
	}

	return NULL;
}

struct connection *get_connection(uint8_t intf_id, uint16_t cport_id)
{
	struct interface *intf;

	intf = get_interface(intf_id);
	if (!intf) {
		pr_err("Invalid interface id %d\n", intf_id);
		return NULL;
	}

	return _get_connection(intf, cport_id);
}

static void *interface_recv(void *data)
{
	int ret;
	uint16_t cport_id;
	struct connection *conn;
	struct interface *intf = data;
	struct controller *ctrl = intf->ctrl;
	uint8_t buffer[GB_NETLINK_MTU];

	while (1) {
		ret = ctrl->intf_read(intf, &cport_id, buffer, GB_NETLINK_MTU);
		if (ret < 0) {
			pr_err("Failed to read data: %d\n", ret);
			continue;
		}

		pr_dump(buffer, ret);

		conn = _get_connection(intf, cport_id);
		if (!conn) {
			pr_err("Received data on invalid cport number\n");
			continue;
		}

		ret = controller_write(AP_INTF_ID, conn->cport1_id, buffer, ret);
		if (ret < 0) {
			pr_err("Failed to transmit data\n");
		}
	}

	return NULL;
}

static uint8_t intf_id_alloc(void)
{
	static uint8_t intf_id;

	pthread_mutex_lock(&intf_alloc_lock);
	intf_id = ++g_intf_id;
	pthread_mutex_unlock(&intf_alloc_lock);

	return intf_id;
}

struct interface *interface_create(struct controller *ctrl, uint32_t vendor_id,
				   uint32_t product_id, uint64_t serial_id,
				   void *priv)
{
	int ret;
	struct interface *intf;

	intf = malloc(sizeof(*intf));
	if (!intf)
		return NULL;

	intf->ctrl = ctrl;
	intf->priv = priv;
	intf->id = intf_id_alloc();
	intf->vendor_id = vendor_id;
	intf->product_id = product_id;
	intf->serial_id = serial_id;

	if (ctrl->interface_create)
		if (ctrl->interface_create(intf))
			goto err_free_intf;

	if (ctrl->intf_read) {
		ret = pthread_create(&intf->thread, NULL, interface_recv, intf);
		if (ret)
			goto err_destroy_intf;
	}

	TAILQ_INSERT_TAIL(&ctrl->interfaces, intf, node);

	return intf;

 err_destroy_intf:
	if (ctrl->interface_destroy)
		ctrl->interface_destroy(intf);
 err_free_intf:
	free(intf);

	return NULL;
}

void interface_destroy(struct interface *intf)
{
	if (intf->ctrl->intf_read) {
		pthread_cancel(intf->thread);
		pthread_join(intf->thread, NULL);
	}

	TAILQ_REMOVE(&intf->ctrl->interfaces, intf, node);

	if (intf->ctrl->interface_destroy)
		intf->ctrl->interface_destroy(intf);
	free(intf);
}

void interfaces_destroy(struct controller *ctrl)
{
	struct interface *intf, *tmp;

	TAILQ_FOREACH_SAFE(intf, &ctrl->interfaces, node, tmp) {
		interface_destroy(intf);
	}
}

int interface_hotplug(struct interface *intf)
{
	int ret;
	ret = svc_send_module_inserted_event(intf->id, intf->vendor_id,
					     intf->product_id, intf->serial_id);

	return ret;
}

int interface_hot_unplug(struct interface *intf)
{
	return 0;
}

struct interface *get_interface(uint8_t intf_id)
{
	struct controller *ctrl;
	struct interface *intf;

	TAILQ_FOREACH(ctrl, &controllers, node) {
		TAILQ_FOREACH(intf, &ctrl->interfaces, node) {
			if (intf->id == intf_id)
				return intf;
		}
	}

	return NULL;
}

void *connection_recv(void *data)
{
	int ret;
	struct connection *conn = data;
	struct interface *intf2 = conn->intf2;
	struct controller *ctrl = intf2->ctrl;
	uint8_t buffer[GB_NETLINK_MTU];

	while (1) {
		ret = ctrl->read(conn, buffer, GB_NETLINK_MTU);
		if (ret < 0) {
			pr_err("Failed to read data: %d\n", ret);
			break;
		}

		if (ret == 0) {
			pr_err("Read is expected to be blocking!\n");
			break;
		}

		pr_dump(buffer, ret);

		ret = controller_write(conn->intf1->id, conn->cport1_id,
				       buffer, ret);
		if (ret < 0) {
			pr_err("Failed to transmit data\n");
		}
	}

	return NULL;
}

int
connection_create(uint8_t intf1_id, uint16_t cport1_id,
		  uint8_t intf2_id, uint16_t cport2_id)
{
	int ret;
	struct interface *intf1;
	struct interface *intf2;
	struct connection *conn;
	struct controller *ctrl;

	intf1 = get_interface(intf1_id);
	if (!intf1) {
		pr_err("Invalid interface id %d\n", intf1_id);
		return -EINVAL;
	}

	intf2 = get_interface(intf2_id);
	if (!intf2) {
		pr_err("Invalid interface id %d\n", intf2_id);
		return -EINVAL;
	}

	conn = malloc(sizeof(*conn));
	if (!conn)
		return -ENOMEM;

	conn->intf1 = intf1;
	conn->intf2 = intf2;
	conn->cport1_id = cport1_id;
	conn->cport2_id = cport2_id;

	ctrl = intf2->ctrl;
	if (ctrl->connection_create) {
		ret = ctrl->connection_create(conn);
		if (ret)
			goto err_free_conn;
	}

	if (ctrl->read) {
		ret = pthread_create(&conn->thread, NULL,
				     connection_recv, conn);
		if (ret)
			goto err_conn_destroy;
	}

	TAILQ_INSERT_TAIL(&connections, conn, node);

	return 0;

err_conn_destroy:
	ctrl->connection_destroy(conn);
err_free_conn:
	free(conn);
	return ret;
}

int
connection_destroy(uint8_t intf1_id, uint16_t cport1_id,
		   uint8_t intf2_id, uint16_t cport2_id)
{
	struct interface *intf2;
	struct connection *conn;
	struct controller *ctrl;

	conn = get_connection(intf1_id, cport1_id);
	if (!conn) {
		pr_err("Failed to get a connection for interface %d cport %d\n",
			intf1_id, cport1_id);
		return -EINVAL;
	}

	intf2 = conn->intf2;
	ctrl = intf2->ctrl;
	if (ctrl->connection_destroy)
		ctrl->connection_destroy(conn);

	TAILQ_REMOVE(&connections, conn, node);
	free(conn);

	return 0;
}

void register_controller(struct controller *controller)
{
	TAILQ_INSERT_TAIL(&controllers, controller, node);
}

void register_controllers(void)
{
#ifdef NETLINK
	register_controller(&netlink_controller);
#endif
#ifdef HAVE_LIBBLUETOOTH
	register_controller(&bluetooth_controller);
#endif
#ifdef HAVE_AVAHI
	register_controller(&avahi_controller);
#endif
#ifdef HAVE_TCPIP
	register_controller(&tcpip_controller);
#endif
}

static void *controller_loop(void *data)
{
	struct controller *ctrl = data;

	ctrl->event_loop_run = 1;
	ctrl->event_loop(ctrl);
	ctrl->event_loop_run = 0;
	pr_dbg("%s: The event loop stopped\n", ctrl->name);

	return NULL;
}

static int controller_loop_init(struct controller *ctrl)
{
	if (!ctrl->event_loop)
		return 0;

	pr_dbg("%s: Creating the event loop thread\n", ctrl->name);
	return pthread_create(&ctrl->thread, NULL, controller_loop, ctrl);
}

static void controller_loop_exit(struct controller *ctrl)
{
	if (!ctrl->event_loop)
		return;

	pr_dbg("%s: Exiting the event loop\n", ctrl->name);
	if (ctrl->event_loop_stop)
		ctrl->event_loop_stop(ctrl);

	if (ctrl->event_loop_run) {
		pr_dbg("%s: Waiting for the thread cancellation\n", ctrl->name);
		pthread_cancel(ctrl->thread);
		pthread_join(ctrl->thread, NULL);
	}
}

int controller_write(uint8_t intf_id, uint16_t cport_id,
		     void *data, size_t len)
{
	struct connection *conn;
	struct controller *ctrl;
	struct interface *intf;

	intf = get_interface(intf_id);
	if (!intf) {
		pr_err("Invalid interface id %d\n", intf_id);
		return -EINVAL;
	}

	conn = _get_connection(intf, cport_id);
	if (!conn) {
		pr_err("Failed to get a connection for interface %d cport %d\n",
			intf_id, cport_id);
		return -EINVAL;
	}

	pr_dump(data, len);

	ctrl = intf->ctrl;
	return ctrl->write(conn, data, len);
}

void controllers_init(void)
{
	int ret;
	struct controller *ctrl, *tmp;

	TAILQ_FOREACH_SAFE(ctrl, &controllers, node, tmp) {
		pr_dbg("%s: Initializing the controller\n", ctrl->name);
		ret = ctrl->init(ctrl);
		if (ret) {
			pr_err("Failed to init %s: %d\n", ctrl->name, ret);
			TAILQ_REMOVE(&controllers, ctrl, node);
			continue;
		}
		TAILQ_INIT(&ctrl->interfaces);
		controller_loop_init(ctrl);
	}
}

void controllers_exit(void)
{
	struct controller *ctrl;

	TAILQ_FOREACH(ctrl, &controllers, node) {
		controller_loop_exit(ctrl);
		interfaces_destroy(ctrl);
		ctrl->exit(ctrl);
	}
}
