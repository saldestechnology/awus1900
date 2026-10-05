// SPDX-License-Identifier: BSD-3-Clause
/* macOS utun socket setup and IPv4 packet I/O. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <unistd.h>
#include "rtl8814au.h"

extern char **environ;

#define DNS_MAX_SERVERS 16
#define DNS_OUTPUT_SIZE 4096

struct dns_server_list {
	char servers[DNS_MAX_SERVERS][46];
	size_t count;
	bool automatic;
};

static int wait_child(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -errno;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -EIO;
	return 0;
}

static int spawn_command(const char *path, char *const argv[], char *output,
			 size_t output_capacity)
{
	posix_spawn_file_actions_t actions;
	pid_t pid;
	int pipefd[2] = {-1, -1}, ret;
	bool capture = output && output_capacity;

	if (capture && pipe(pipefd) < 0)
		return -errno;
	ret = posix_spawn_file_actions_init(&actions);
	if (ret) {
		if (capture) {
			close(pipefd[0]);
			close(pipefd[1]);
		}
		return -ret;
	}
	if (capture) {
		posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
		posix_spawn_file_actions_addclose(&actions, pipefd[0]);
		posix_spawn_file_actions_addclose(&actions, pipefd[1]);
	}
	ret = posix_spawn(&pid, path, &actions, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&actions);
	if (capture)
		close(pipefd[1]);
	if (ret) {
		if (capture)
			close(pipefd[0]);
		return -ret;
	}
	if (capture) {
		size_t used = 0;

		while (used + 1 < output_capacity) {
			ssize_t n = read(pipefd[0], output + used, output_capacity - used - 1);
			if (n > 0) {
				used += (size_t)n;
				continue;
			}
			if (!n)
				break;
			if (errno == EINTR)
				continue;
			ret = -errno;
			close(pipefd[0]);
			wait_child(pid);
			return ret;
		}
		output[used] = '\0';
		close(pipefd[0]);
	}
	return wait_child(pid);
}

static bool valid_ifname(const char *name)
{
	if (!name || strncmp(name, "utun", 4) || !name[4])
		return false;
	for (const char *p = name + 4; *p; p++)
		if (*p < '0' || *p > '9')
			return false;
	return true;
}

static void bytes_to_ip(const u8 bytes[4], char out[16])
{
	struct in_addr address;

	memcpy(&address.s_addr, bytes, sizeof(address.s_addr));
	if (!inet_ntop(AF_INET, &address, out, 16))
		out[0] = '\0';
}

static bool copy_line_value(const char *text, const char *key, char *out, size_t cap)
{
	const char *line = strstr(text, key);
	size_t len;

	if (!line)
		return false;
	line += strlen(key);
	while (*line == ' ' || *line == '\t')
		line++;
	len = strcspn(line, " \t\r\n");
	if (!len || len >= cap)
		return false;
	memcpy(out, line, len);
	out[len] = '\0';
	return true;
}

static int parse_dns_server_list(const char *output, struct dns_server_list *list)
{
	const char *line = output;

	memset(list, 0, sizeof(*list));
	if (strstr(output, "There aren't any DNS Servers set")) {
		list->automatic = true;
		return 0;
	}
	while (*line) {
		char address[46];
		const char *end = line + strcspn(line, "\r\n");
		const char *start = line;
		size_t len;
		u8 binary[16];

		while (start < end && (*start == ' ' || *start == '\t'))
			start++;
		while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		len = (size_t)(end - start);
		if (len) {
			if (len >= sizeof(address))
				return -EINVAL;
			memcpy(address, start, len);
			address[len] = '\0';
			if (inet_pton(AF_INET, address, binary) != 1 &&
			    inet_pton(AF_INET6, address, binary) != 1)
				return -EINVAL;
			if (list->count == DNS_MAX_SERVERS)
				return -E2BIG;
			snprintf(list->servers[list->count++], sizeof(list->servers[0]), "%s", address);
		}
		line += strcspn(line, "\r\n");
		while (*line == '\r' || *line == '\n')
			line++;
	}
	return list->count ? 0 : -EIO;
}

static int get_system_dns(const char *service, struct dns_server_list *list)
{
	char output[DNS_OUTPUT_SIZE] = {0};
	char *argv[] = {"networksetup", "-getdnsservers", (char *)service, NULL};
	int ret = spawn_command("/usr/sbin/networksetup", argv, output, sizeof(output));

	if (ret)
		return ret;
	return parse_dns_server_list(output, list);
}

static int set_system_dns(const char *service, const struct dns_server_list *list)
{
	char *argv[DNS_MAX_SERVERS + 4];
	size_t argc = 0;

	argv[argc++] = "networksetup";
	argv[argc++] = "-setdnsservers";
	argv[argc++] = (char *)service;
	if (list->automatic) {
		argv[argc++] = "Empty";
	} else {
		if (!list->count || list->count > DNS_MAX_SERVERS)
			return -EINVAL;
		for (size_t i = 0; i < list->count; i++)
			argv[argc++] = (char *)list->servers[i];
	}
	argv[argc] = NULL;
	return spawn_command("/usr/sbin/networksetup", argv, NULL, 0);
}

static bool dns_list_is_session_value(const struct dns_server_list *list,
				      const char *session_dns)
{
	return !list->automatic && list->count == 1 &&
	       !strcmp(list->servers[0], session_dns);
}

static int restore_system_dns(struct rtl_utun *utun)
{
	struct dns_server_list current = {0}, previous = {0};
	int ret;

	if (!utun->system_dns_changed)
		return 0;
	ret = get_system_dns(utun->dns_service, &current);
	if (ret)
		return ret;
	if (!dns_list_is_session_value(&current, utun->session_dns)) {
		/* Preserve an administrator's DNS edit made while the tunnel was active. */
		utun->system_dns_changed = false;
		return 0;
	}
	previous.count = utun->previous_dns_count;
	previous.automatic = utun->previous_dns_automatic;
	for (size_t i = 0; i < previous.count; i++)
		snprintf(previous.servers[i], sizeof(previous.servers[i]), "%s", utun->previous_dns[i]);
	ret = set_system_dns(utun->dns_service, &previous);
	if (!ret)
		utun->system_dns_changed = false;
	return ret;
}

static int configure_system_dns(struct rtl_utun *utun,
				const struct rtl_dhcp_client *dhcp,
				const char *service)
{
	struct dns_server_list previous = {0}, desired = {0}, verify = {0};
	char dns[16];
	int ret;

	if (!service)
		return 0;
	if (!*service || strnlen(service, sizeof(utun->dns_service)) >= sizeof(utun->dns_service))
		return -EINVAL;
	bytes_to_ip(dhcp->dns, dns);
	if (!dns[0] || !strcmp(dns, "0.0.0.0"))
		return -ENODATA;
	ret = get_system_dns(service, &previous);
	if (ret)
		return ret;
	snprintf(utun->dns_service, sizeof(utun->dns_service), "%s", service);
	utun->previous_dns_count = previous.count;
	utun->previous_dns_automatic = previous.automatic;
	for (size_t i = 0; i < previous.count; i++)
		snprintf(utun->previous_dns[i], sizeof(utun->previous_dns[i]), "%s",
			 previous.servers[i]);
	snprintf(utun->session_dns, sizeof(utun->session_dns), "%s", dns);
	desired.count = 1;
	snprintf(desired.servers[0], sizeof(desired.servers[0]), "%s", dns);
	utun->system_dns_changed = true;
	ret = set_system_dns(service, &desired);
	if (ret)
		return ret;
	ret = get_system_dns(service, &verify);
	if (ret || !dns_list_is_session_value(&verify, dns))
		return ret ? ret : -EIO;
	printf("system DNS on '%s' set to DHCP server %s for this session\n", service, dns);
	return 0;
}

int rtl_utun_refresh_dns(struct rtl_utun *utun, const struct rtl_dhcp_client *dhcp)
{
	struct dns_server_list current = {0}, desired = {0}, verify = {0};
	char dns[16];
	int ret;

	if (!utun || !dhcp)
		return -EINVAL;
	if (!utun->system_dns_changed)
		return 0;
	bytes_to_ip(dhcp->dns, dns);
	if (!dns[0] || !strcmp(dns, "0.0.0.0"))
		return -ENODATA;
	if (!strcmp(dns, utun->session_dns))
		return 0;
	ret = get_system_dns(utun->dns_service, &current);
	if (ret)
		return ret;
	if (!dns_list_is_session_value(&current, utun->session_dns)) {
		/* Do not overwrite a DNS change made by the user during the session. */
		utun->system_dns_changed = false;
		return 0;
	}
	desired.count = 1;
	snprintf(desired.servers[0], sizeof(desired.servers[0]), "%s", dns);
	ret = set_system_dns(utun->dns_service, &desired);
	if (ret)
		return ret;
	ret = get_system_dns(utun->dns_service, &verify);
	if (ret || !dns_list_is_session_value(&verify, dns))
		return ret ? ret : -EIO;
	snprintf(utun->session_dns, sizeof(utun->session_dns), "%s", dns);
	printf("DHCP DNS changed; system DNS on '%s' updated to %s\n",
	       utun->dns_service, dns);
	return 0;
}

static int get_default_route(char *gateway, size_t gateway_capacity,
			     char *ifname, size_t ifname_capacity)
{
	char output[2048] = {0};
	char *argv[] = {"route", "-n", "get", "-inet", "default", NULL};
	int ret;

	ret = spawn_command("/sbin/route", argv, output, sizeof(output));
	if (ret)
		return ret;
	if (!copy_line_value(output, "gateway:", gateway, gateway_capacity) ||
	    !copy_line_value(output, "interface:", ifname, ifname_capacity))
		return -EIO;
	if (strnlen(ifname, ifname_capacity) == ifname_capacity ||
	    strspn(ifname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != strlen(ifname))
		return -EINVAL;
	return 0;
}

static int save_default_route(struct rtl_utun *utun)
{
	char gateway[16], ifname[32];
	struct in_addr parsed;
	int ret = get_default_route(gateway, sizeof(gateway), ifname, sizeof(ifname));

	if (ret)
		return ret;
	if (!strncmp(gateway, "link#", 5))
		utun->previous_default_interface = true;
	else if (inet_pton(AF_INET, gateway, &parsed) != 1)
		return -EINVAL;
	snprintf(utun->previous_gateway, sizeof(utun->previous_gateway), "%s", gateway);
	snprintf(utun->previous_ifname, sizeof(utun->previous_ifname), "%s", ifname);
	return 0;
}

static int restore_default_route(struct rtl_utun *utun)
{
	char gateway[16], ifname[32];
	char *argv_gateway[] = {"route", "-n", "change", "-inet", "default",
				utun->previous_gateway, "-ifp", utun->previous_ifname, NULL};
	char *argv_interface[] = {"route", "-n", "change", "-inet", "default",
				  "-interface", utun->previous_ifname, NULL};
	int ret;

	if (!utun->default_route_changed)
		return 0;
	ret = get_default_route(gateway, sizeof(gateway), ifname, sizeof(ifname));
	if (ret || strcmp(ifname, utun->ifname)) {
		/* Keep a route change made by the system or user while this session ran. */
		utun->default_route_changed = false;
		return 0;
	}
	ret = spawn_command("/sbin/route", utun->previous_default_interface ?
			    argv_interface : argv_gateway, NULL, 0);
	if (!ret)
		utun->default_route_changed = false;
	return ret;
}

int rtl_utun_open(struct rtl_utun *utun)
{
	struct ctl_info info = {0};
	struct sockaddr_ctl address = {0};
	socklen_t name_len;
	int flags;

	if (!utun)
		return -EINVAL;
	memset(utun, 0, sizeof(*utun));
	utun->fd = -1;
	utun->fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (utun->fd < 0)
		return -errno;
	strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
	if (ioctl(utun->fd, CTLIOCGINFO, &info) < 0)
		goto fail;
	address.sc_len = sizeof(address);
	address.sc_family = AF_SYSTEM;
	address.ss_sysaddr = AF_SYS_CONTROL;
	address.sc_id = info.ctl_id;
	address.sc_unit = 0; /* Kernel selects the first available utun unit. */
	if (connect(utun->fd, (struct sockaddr *)&address, sizeof(address)) < 0)
		goto fail;
	name_len = sizeof(utun->ifname);
	if (getsockopt(utun->fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
		       utun->ifname, &name_len) < 0)
		goto fail;
	if (name_len >= sizeof(utun->ifname))
		name_len = sizeof(utun->ifname) - 1;
	utun->ifname[name_len] = '\0';
	if (!valid_ifname(utun->ifname)) {
		errno = EPROTO;
		goto fail;
	}
	flags = fcntl(utun->fd, F_GETFL, 0);
	if (flags < 0 || fcntl(utun->fd, F_SETFL, flags | O_NONBLOCK) < 0)
		goto fail;
	return 0;
fail:
	{
		int error = errno;
		close(utun->fd);
		utun->fd = -1;
		return -error;
	}
}

int rtl_utun_configure(struct rtl_utun *utun, const struct rtl_dhcp_client *dhcp,
		       bool default_route, const char *dns_service)
{
	char address[16], gateway[16], netmask[16];
	char *ifconfig_argv[10];
	char *route_argv[9];
	int ret;

	if (!utun || utun->fd < 0 || !dhcp || dhcp->state != RTL_DHCP_BOUND ||
	    !valid_ifname(utun->ifname) || (dns_service && !default_route))
		return -EINVAL;
	bytes_to_ip(dhcp->address, address);
	bytes_to_ip(dhcp->gateway, gateway);
	bytes_to_ip(dhcp->netmask, netmask);
	if (!*address || !*gateway || !*netmask)
		return -EINVAL;
	if (default_route) {
		ret = save_default_route(utun);
		if (ret)
			return ret;
	}
	ifconfig_argv[0] = "ifconfig";
	ifconfig_argv[1] = utun->ifname;
	ifconfig_argv[2] = "inet";
	ifconfig_argv[3] = address;
	ifconfig_argv[4] = gateway;
	ifconfig_argv[5] = "netmask";
	ifconfig_argv[6] = netmask;
	ifconfig_argv[7] = "up";
	ifconfig_argv[8] = NULL;
	ret = spawn_command("/sbin/ifconfig", ifconfig_argv, NULL, 0);
	if (ret)
		return ret;
	utun->configured = true;
	if (!default_route)
		return 0;
	route_argv[0] = "route";
	route_argv[1] = "-n";
	route_argv[2] = "change";
	route_argv[3] = "-inet";
	route_argv[4] = "default";
	route_argv[5] = "-interface";
	route_argv[6] = utun->ifname;
	route_argv[7] = NULL;
	utun->default_route_changed = true;
	ret = spawn_command("/sbin/route", route_argv, NULL, 0);
	if (ret) {
		restore_default_route(utun);
		return ret;
	}
	return configure_system_dns(utun, dhcp, dns_service);
}

int rtl_utun_read_ipv4(struct rtl_utun *utun, u8 *packet, size_t capacity,
		       size_t *packet_len)
{
	u8 buffer[65536];
	u32 family;
	ssize_t n;
	size_t len, ihl, ip_len;

	if (!utun || utun->fd < 0 || !packet || !packet_len)
		return -EINVAL;
	n = read(utun->fd, buffer, sizeof(buffer));
	if (n < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK) ? -EAGAIN : -errno;
	if (n < 4)
		return -EBADMSG;
	memcpy(&family, buffer, sizeof(family)); /* utun's address-family word is native endian. */
	len = (size_t)n - sizeof(family);
	if (family != AF_INET || len > capacity || len < 20 || (buffer[4] >> 4) != 4)
		return -EMSGSIZE;
	ihl = (size_t)(buffer[4] & 0x0f) * 4;
	ip_len = (size_t)buffer[6] << 8 | buffer[7];
	if (ihl < 20 || ihl > len || ip_len < ihl || ip_len > len)
		return -EBADMSG;
	memcpy(packet, buffer + sizeof(family), ip_len);
	*packet_len = ip_len;
	return 0;
}

int rtl_utun_write_ipv4(struct rtl_utun *utun, const u8 *packet, size_t packet_len)
{
	u8 buffer[4 + 65535];
	u32 family = AF_INET;
	ssize_t n;
	size_t ihl, ip_len;

	if (!utun || utun->fd < 0 || !packet || packet_len < 20 || packet_len > 65535 ||
	    (packet[0] >> 4) != 4)
		return -EINVAL;
	ihl = (size_t)(packet[0] & 0x0f) * 4;
	ip_len = (size_t)packet[2] << 8 | packet[3];
	if (ihl < 20 || ihl > packet_len || ip_len < ihl || ip_len > packet_len)
		return -EBADMSG;
	memcpy(buffer, &family, sizeof(family));
	memcpy(buffer + sizeof(family), packet, ip_len);
	n = write(utun->fd, buffer, sizeof(family) + ip_len);
	if (n < 0)
		return -errno;
	return (size_t)n == sizeof(family) + ip_len ? 0 : -EIO;
}

void rtl_utun_close(struct rtl_utun *utun)
{
	if (!utun)
		return;
	if (utun->fd >= 0) {
		int ret = restore_default_route(utun);
		if (ret)
			fprintf(stderr, "warning: could not restore previous IPv4 default route: %s\n",
				strerror(-ret));
		ret = restore_system_dns(utun);
		if (ret)
			fprintf(stderr, "warning: could not restore DNS settings for '%s': %s\n",
				utun->dns_service, strerror(-ret));
		if (utun->configured) {
			char *argv[] = {"ifconfig", utun->ifname, "down", NULL};
			spawn_command("/sbin/ifconfig", argv, NULL, 0);
		}
		close(utun->fd);
	}
	memset(utun, 0, sizeof(*utun));
	utun->fd = -1;
}
