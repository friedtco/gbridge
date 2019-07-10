/*
 * GBridge (Greybus Bridge)
 * Copyright (c) 2016 Alexandre Bailon
 * Copyright (c) 2019 Christopher Friedt
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
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <debug.h>
#include <gbridge.h>
#include <controller.h>

// this 'G' << 8 | 'B' works out to 18242
#define GBRIDGE_TCPIP_PORT                        \
	(                                         \
		0                                 \
		| ((unsigned)('G' << 8) & 0xff00) \
		| ((unsigned)('B' << 0) & 0x00ff) \
	)

struct tcpip_connection {
	int sock;
};

struct tcpip_device {
	int client_socket;
	char *host_name;
	char addr[INET6_ADDRSTRLEN];
	int port;
};

struct tcpip_controller {
	struct sockaddr_in6 server_sockaddr;
	int server_socket;
	// socket[1] is written to to cancel the server thread
	int cancel_socket[2];
};

static int tcpip_connection_create(struct connection *conn)
{
	struct tcpip_device *td = conn->intf1->priv;
	pr_info("Connected to module at %s:%d\n", td->addr, td->port);
	return 0;
}

static int tcpip_connection_destroy(struct connection *conn)
{
	struct tcpip_device *td = conn->intf1->priv;

	if (NULL == conn || NULL == conn->intf1 || NULL == conn->intf1->priv ) {
		return 0;
	}

	if (NULL != td->host_name) {
		free( td->host_name );
		td->host_name = NULL;
	}

	if (-1 != td->client_socket) {
		close(td->client_socket);
		td->client_socket = -1;
	}
	free(td);
	conn->intf1->priv = NULL;

	return 0;
}

static void tcpip_hotplug(struct controller *ctrl, const int client_socket, const char *host_name,
			  const struct sockaddr *sa, const socklen_t salen )
{
	struct interface *intf;
	struct tcpip_device *td;

	td = malloc(sizeof(*td));
	if (!td)
		goto err_exit;

	td->client_socket = client_socket;
	td->host_name = (char *)host_name;
	inet_ntop(sa->sa_family, sa, td->addr, sizeof(td->addr));

	switch (sa->sa_family) {
	case AF_INET:
		td->port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		break;
	case AF_INET6:
		td->port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		break;
	default:
		pr_err("unrecognized address family %d\n", sa->sa_family);
		goto err_free_host_name;
	}

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
	close(client_socket);
	free(td->host_name);
	free(td);
err_exit:
	pr_err("Failed to hotplug TCP/IP module\n");
}

static void tcpip_intf_destroy(struct interface *intf)
{
}

static int tcpip_discovery(struct controller *ctrl)
{
	struct tcpip_controller *tcpip_ctrl;

	if (NULL == ctrl || NULL == ctrl->priv) {
		return -EINVAL;
	}

	int r;

	tcpip_ctrl = ctrl->priv;

	int client_socket;
	struct sockaddr_in6 client_sockaddr6;
	struct sockaddr *sa;
	socklen_t salen;

	fd_set rfds;

	for( ;; ) {

		FD_ZERO(&rfds);
		FD_SET(tcpip_ctrl->server_socket, &rfds);
		FD_SET(tcpip_ctrl->cancel_socket[0], &rfds);
		int maxfd = (tcpip_ctrl->server_socket >= tcpip_ctrl->cancel_socket[0])
			? tcpip_ctrl->server_socket : tcpip_ctrl->cancel_socket[0];

		r = select(maxfd+1, &rfds, NULL, NULL, NULL);
		if (-1 == r) {
			r = errno;
			pr_err("Failed in call to select\n");
			break;
		}
		if (0 == r) {
			r = errno;
			pr_err("select timed-out (even though no timeout was specified\n");
			break;
		}
		if (FD_ISSET(tcpip_ctrl->cancel_socket[0], &rfds)) {
			r = 0;
			pr_info("received notification to cancel discovery\n");
			break;
		}

		// to accept on both ipv4 and ipv6 at the same time
		r = accept(tcpip_ctrl->server_socket, NULL, NULL);
		if (-1 == r) {
			r = errno;
			pr_err("Failed in call to accept\n");
			return r;
		}
		client_socket = r;

		sa = (struct sockaddr *)&client_sockaddr6;
		salen = sizeof(client_sockaddr6);

		r = getpeername(client_socket, sa, &salen);
		if (-1 == r) {
			pr_err("Failed in call to getpeername\n");
			close(client_socket);
			break;
		}

		if ( !( AF_INET == sa->sa_family || AF_INET6 == sa->sa_family ) ) {
			r = EINVAL;
			pr_err("unrecognized address family %d\n", sa->sa_family);
			break;
		}

		char *hostname = calloc(1, NI_MAXHOST);
		if (NULL == hostname) {
			r = ENOMEM;
			pr_err("failed to allocate memory for hostname");
			close(client_socket);
			break;
		}
		r = getnameinfo( sa, salen, hostname, NI_MAXHOST, NULL, 0, 0 );
		hostname = realloc(hostname, strlen(hostname) + 1);

		tcpip_hotplug(ctrl, client_socket, hostname, sa, salen);
	}

	return r;
}

static void tcpip_discovery_stop(struct controller *ctrl)
{
	if (NULL == ctrl || NULL == ctrl->priv) {
		return;
	}
	struct tcpip_controller *tcpip_ctrl = ctrl->priv;
	int r;
	r = write(tcpip_ctrl->cancel_socket[1], "Q", 1);
	if (1 != r) {
		pr_err("Failed in call to write\n");
		return;
	}
	for( ; ctrl->event_loop_run; );
}

static int tcpip_write(struct connection *conn, void *data, size_t len)
{
	struct tcpip_connection *tconn = conn->priv;

	return write(tconn->sock, data, len);
}

static int tcpip_read(struct connection *conn, void *data, size_t len)
{
	struct tcpip_connection *tconn = conn->priv;

	return read(tconn->sock, data, len);
}

static int tcpip_init(struct controller *ctrl)
{
	int r;
	struct tcpip_controller *tcpip_ctrl;

	tcpip_ctrl = calloc(1,sizeof(*tcpip_ctrl));
	if (!tcpip_ctrl) {
		r = -ENOMEM;
		goto out;
	}
	ctrl->priv = tcpip_ctrl;

	r = socket(AF_INET6, SOCK_STREAM, 0);
	if (-1 == r) {
		r = -errno;
		pr_err("Failed to create socket\n");
		goto free_tcpip_ctrl;
	}
	tcpip_ctrl->server_socket = r;

	int on = 1;
	r = setsockopt(tcpip_ctrl->server_socket, SOL_SOCKET, SO_REUSEADDR, & on, sizeof(on));
	if (-1 == r) {
		r = -errno;
		pr_err("Failed in call to setsockopt\n");
		goto close_socket;
	}

	memset(&tcpip_ctrl->server_sockaddr, 0, sizeof(tcpip_ctrl->server_sockaddr));
	tcpip_ctrl->server_sockaddr.sin6_family = AF_INET6;
	tcpip_ctrl->server_sockaddr.sin6_addr   = in6addr_any;
	tcpip_ctrl->server_sockaddr.sin6_port   = htons(GBRIDGE_TCPIP_PORT);

	r = bind(tcpip_ctrl->server_socket, (struct sockaddr *)&tcpip_ctrl->server_sockaddr, sizeof(tcpip_ctrl->server_sockaddr));
	if (-1 == r) {
		r = -errno;
		pr_err("Failed in call to bind\n");
		goto close_socket;
	}

	r = listen(tcpip_ctrl->server_socket, 10);
	if (-1 == r) {
		r = -errno;
		pr_err("Failed in call to listen\n");
		goto close_socket;
	}
	pr_info("TCP/IP: Listening on port %u\n", GBRIDGE_TCPIP_PORT);

	r = socketpair(AF_UNIX, SOCK_STREAM, 0, tcpip_ctrl->cancel_socket);
	if (-1 == r) {
		r = -errno;
		pr_err("Failed in call to socketpair\n");
		goto close_socket;
	}

	// success!
	r = 0;
	goto out;

close_socket:
	close(tcpip_ctrl->server_socket);

free_tcpip_ctrl:
	free(tcpip_ctrl);
	ctrl->priv = NULL;

out:
	return r;
}

static void tcpip_exit(struct controller *ctrl)
{
	if (NULL == ctrl || NULL == ctrl->priv) {
		return;
	}

	struct tcpip_controller *tcpip_ctrl = ctrl->priv;

	if ( -1 != tcpip_ctrl->server_socket ) {
		close(tcpip_ctrl->server_socket);
		tcpip_ctrl->server_socket = -1;
	}

	if ( -1 != tcpip_ctrl->cancel_socket[0] ) {
		close(tcpip_ctrl->cancel_socket[0]);
		tcpip_ctrl->cancel_socket[0] = -1;
	}

	if ( -1 != tcpip_ctrl->cancel_socket[1] ) {
		close(tcpip_ctrl->cancel_socket[1]);
		tcpip_ctrl->cancel_socket[1] = -1;
	}

	free(ctrl->priv);
	ctrl->priv = NULL;
	tcpip_ctrl = NULL;
}


struct controller tcpip_controller = {
	.name = "TCP/IP",
	.init = tcpip_init,
	.exit = tcpip_exit,
	.connection_create = tcpip_connection_create,
	.connection_destroy = tcpip_connection_destroy,
	.event_loop = tcpip_discovery,
	.event_loop_stop = tcpip_discovery_stop,
	.write = tcpip_write,
	.read = tcpip_read,
	.interface_destroy = tcpip_intf_destroy,
};
