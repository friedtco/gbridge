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

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

#include <debug.h>
#include <gbridge.h>
#include <controller.h>

#if SSL
#include "pkauth.h"
#endif

extern void dump_msg(const char *func, struct gb_operation_msg_hdr *msg);

struct tcpip_connection {
	int sock;
#if SSL
	uint8_t *session_key;
	size_t session_key_len;
#endif
};

struct tcpip_device {
	char *host_name;
	char addr[AVAHI_ADDRESS_STR_MAX];
	int port;
};

struct tcpip_controller {
	AvahiClient *client;
	AvahiSimplePoll *simple_poll;
};

static int tcpip_connection_create(struct connection *conn)
{
	int ret;
	struct sockaddr_in6 serv_addr;
	struct tcpip_connection *tconn;
	struct tcpip_device *td = conn->intf2->priv;

	tconn = malloc(sizeof(*tconn));
	if (!tconn)
		return -ENOMEM;

	tconn->sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (tconn->sock < 0) {
		pr_err("Can't create socket\n");
		return tconn->sock;
	}
	conn->priv = tconn;

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin6_family = AF_INET6;
	serv_addr.sin6_port = htons(td->port + conn->cport2_id);
#if 0
	serv_addr.sin6_addr.s_addr = inet_addr(td->addr);
#else
	inet_pton(AF_INET6, td->addr, &serv_addr.sin6_addr);
#endif

	pr_info("Trying to connect to module at %s:%d\n", td->addr, td->port);
	do {
		ret = connect(tconn->sock,
			      (struct sockaddr *)&serv_addr,
			      sizeof(serv_addr));
		if (ret)
			sleep(1);
	} while (ret);

#if SSL
	tconn->session_key_len = 16; // AES-128
	ret = pkauth_enticate(tconn->sock, &tconn->session_key, tconn->session_key_len);
	if (ret) {
		close(tconn->sock);
		free(tconn);
		pr_err("Public-key authentication failed with module at %s:%d\n",
			td->addr, td->port);
		return ret;
	}
#endif

	pr_info("Connected to module\n");

	return 0;
}

static int tcpip_connection_destroy(struct connection *conn)
{
	struct tcpip_connection *tconn = conn->priv;

	conn->priv = NULL;
	close(tconn->sock);
	free(tconn);

	return 0;
}

static void tcpip_hotplug(struct controller *ctrl, const char *host_name,
			  const AvahiAddress *address, uint16_t port)
{
	struct interface *intf;
	struct tcpip_device *td;

	td = malloc(sizeof(*td));
	if (!td)
		goto exit;

#if 0
	td->port = port;
	avahi_address_snprint(td->addr, sizeof(td->addr), address);
	td->host_name = malloc(strlen(host_name) + 1);
#else
	td->port = 4242;
	snprintf(td->addr, sizeof(td->addr), "2001:db8::1");
#endif
	if (!td->host_name)
		goto err_free_td;
	strcpy(td->host_name, host_name);

	/* FIXME: use real IDs */
	intf = interface_create(ctrl, 1, 1, 0x1234, td);
	if (!intf)
		goto err_free_host_name;

	if (interface_hotplug(intf))
		goto err_intf_destroy;

	return;

err_intf_destroy:
	interface_destroy(intf);
err_free_host_name:
	free(td->host_name);
err_free_td:
	free(td);
exit:
	pr_err("Failed to hotplug of TCP/IP module\n");
}

static void resolve_callback(AvahiServiceResolver *r,
			     AvahiIfIndex interface,
			     AvahiProtocol protocol,
			     AvahiResolverEvent event,
			     const char *name,
			     const char *type,
			     const char *domain,
			     const char *host_name,
			     const AvahiAddress *address,
			     uint16_t port,
			     AvahiStringList *txt,
			     AvahiLookupResultFlags flags,
			     void* userdata)
{
	AvahiClient *c;
	struct controller *ctrl = userdata;

	switch (event) {
	case AVAHI_RESOLVER_FAILURE:
		c = avahi_service_resolver_get_client(r);
		pr_err("(Resolver) Failed to resolve service"
			" '%s' of type '%s' in domain '%s': %s\n",
			name, type, domain,
			avahi_strerror(avahi_client_errno(c)));
		break;

	case AVAHI_RESOLVER_FOUND:
		tcpip_hotplug(ctrl, host_name, address, port);
		break;
	}

	avahi_service_resolver_free(r);
}

static void browse_callback(AvahiServiceBrowser *b,
			    AvahiIfIndex interface,
			    AvahiProtocol protocol,
			    AvahiBrowserEvent event,
			    const char *name,
			    const char *type,
			    const char *domain,
			    AvahiLookupResultFlags flags,
			    void* userdata)
{
	struct controller *ctrl = userdata;
	struct tcpip_controller *tcpip_ctrl = ctrl->priv;
	AvahiClient *c = tcpip_ctrl->client;
	AvahiServiceResolver *r;

	switch (event) {
	case AVAHI_BROWSER_FAILURE:
		c = avahi_service_browser_get_client(b);
		pr_err("(Browser) %s\n", 
			avahi_strerror(avahi_client_errno(c)));
		avahi_simple_poll_quit(tcpip_ctrl->simple_poll);
		return;

	case AVAHI_BROWSER_NEW:
		r = avahi_service_resolver_new(c, interface, protocol,
					       name, type, domain,
					       AVAHI_PROTO_UNSPEC, 0,
					       resolve_callback, userdata);
		if (!r) {
			pr_err("Failed to resolve service '%s': %s\n",
				name, avahi_strerror(avahi_client_errno(c)));
		}

		return;

	case AVAHI_BROWSER_REMOVE:
		/* TODO */
		return;

	default:
		return;
	}
}

static void client_callback(AvahiClient *c,
			    AvahiClientState state, void *userdata)
{
	struct controller *ctrl = userdata;
	struct tcpip_controller *tcpip_ctrl = ctrl->priv;

	if (state == AVAHI_CLIENT_FAILURE) {
		pr_err("Server connection failure: %s\n",
			avahi_strerror(avahi_client_errno(c)));
		avahi_simple_poll_quit(tcpip_ctrl->simple_poll);
	}
}

static void tcpip_intf_destroy(struct interface *intf)
{
}

static int avahi_discovery(struct controller *ctrl)
{
	AvahiClient *client;
	AvahiServiceBrowser *sb;
	AvahiSimplePoll *simple_poll;
	struct tcpip_controller *tcpip_ctrl = ctrl->priv;
	int ret = 0;
	int error;

	simple_poll = avahi_simple_poll_new();
	if (!simple_poll) {
		pr_err("Failed to create simple poll object\n");
		return -ENOMEM;
	}

	client = avahi_client_new(avahi_simple_poll_get(simple_poll),
				  0, client_callback, ctrl, &error);
	if (!client) {
		ret = error;
		pr_err("Failed to create client: %s\n", avahi_strerror(error));
		goto err_simple_pool_free;
	}

	tcpip_ctrl->client = client;
	sb = avahi_service_browser_new(client,
				       AVAHI_IF_UNSPEC, AVAHI_PROTO_INET,
				       "_greybus._tcp", NULL, 0,
				       browse_callback, ctrl); 
	if (!sb) {
		ret = avahi_client_errno(client);
		pr_err("Failed to create service browser: %s\n",
			avahi_strerror(avahi_client_errno(client)));
		goto err_client_free;
	}

	tcpip_ctrl->simple_poll = simple_poll;

#if 1
	tcpip_hotplug(ctrl, "ble", NULL, 4242);
#endif


	avahi_simple_poll_loop(simple_poll);

	avahi_service_browser_free(sb);
err_client_free:
	avahi_client_free(client);
err_simple_pool_free:
	avahi_simple_poll_free(simple_poll);

	return ret;
}

static void avahi_discovery_stop(struct controller *ctrl)
{
	struct tcpip_controller *tcpip_ctrl = ctrl->priv;
	avahi_simple_poll_quit(tcpip_ctrl->simple_poll);
}

static int tcpip_write(struct connection *conn, void *data, size_t len)
{
	struct tcpip_connection *tconn = conn->priv;
#if SSL
	if ( pkauth_initialized() ) {
		return pkauth_write(tconn->sock, tconn->session_key, tconn->session_key_len, data, len);
	}
#endif

	dump_msg(__func__, data);

	return write(tconn->sock, data, len);
}

static int _tcpip_read(int fd, void *data, size_t len)
{
	int ret;
	size_t remaining;
	size_t offset;
	size_t recvd;

	if (0 == len) {
		return 0;
	}

	for(remaining = len, offset = 0, recvd = 0; remaining; remaining -= recvd, offset += recvd, recvd = 0) {
		ret = read(fd, &((uint8_t *)data)[offset], remaining);
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

static int tcpip_read(struct connection *conn, void *data, size_t len)
{
	struct tcpip_connection *tconn = conn->priv;
#if SSL
	if ( pkauth_initialized() ) {
		return pkauth_read(tconn->sock, tconn->session_key, tconn->session_key_len, data, len);
	}
#endif

	int ret;
	uint8_t *p_data = data;
	size_t msg_size;
	size_t payload_size;

	ret = _tcpip_read(tconn->sock, p_data, sizeof(struct gb_operation_msg_hdr));
	if (ret) {
		pr_err("Failed to get header\n");
		return ret;
	}

	msg_size = gb_operation_msg_size(data);
	payload_size = msg_size - sizeof(struct gb_operation_msg_hdr);
	p_data += sizeof(struct gb_operation_msg_hdr);

	ret = _tcpip_read(tconn->sock, p_data, payload_size);
	if (ret < 0) {
		pr_err("Failed to get payload\n");
		return ret;
	}

	dump_msg(__func__, data);

	return msg_size;
}

static int tcpip_init(struct controller *ctrl)
{
	struct tcpip_controller *tcpip_ctrl;

	tcpip_ctrl = malloc(sizeof(*tcpip_ctrl));
	if (!tcpip_ctrl)
		return -ENOMEM;
	 ctrl->priv = tcpip_ctrl;

	return 0;
}

static void tcpip_exit(struct controller *ctrl)
{
	free(ctrl->priv);
}


struct controller tcpip_controller = {
	.name = "TCP/IP",
	.init = tcpip_init,
	.exit = tcpip_exit,
	.connection_create = tcpip_connection_create,
	.connection_destroy = tcpip_connection_destroy,
	.event_loop = avahi_discovery,
	.event_loop_stop = avahi_discovery_stop,
	.write = tcpip_write,
	.read = tcpip_read,
	.interface_destroy = tcpip_intf_destroy,
};
