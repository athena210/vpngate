# vpngate

## 1. Project status

**This version of the project is deprecated.** The project is planned to be redesigned as a distributed L3 VPN network.

### Known OpenVPN compatibility issues

The Alpine Linux 3.23 branch uses OpenVPN 2.6. Specifically, the current package for Alpine 3.23 is OpenVPN 2.6.23. This version supports running both `strong` and `compat` configurations simultaneously.

OpenVPN 2.6.20 had security issues related to the use of `tls-crypt-v2`, including memory leaks when processing client keys, which could lead to memory exhaustion and server crashes. Fixes were included in OpenVPN 2.6.21. Therefore, a newer patched version, such as 2.6.23, should be used for the `strong` configuration.

Another compatibility issue was introduced in OpenVPN 2.7.6. This version tightened validation of the first control channel `HARD_RESET` packet: the server now accepts it only if its `packet ID` is zero. The built-in client in older MikroTik RouterOS v6 versions sends the first packet with `packet ID = 1`, preventing the connection from being established.

Therefore, the choice of OpenVPN version depends on whether support for older MikroTik clients is required:

| Version | `strong` | `compat` |
|---|---|---|
| OpenVPN 2.6.20 | Not recommended due to known security issues | Compatible |
| OpenVPN 2.6.21–2.6.23 | Compatible | Compatible |
| OpenVPN 2.7.6 | Compatible | Incompatible with older MikroTik RouterOS v6 versions |

Both OpenVPN configurations can be used independently or alongside the IPsec server.

## 2. Project purpose

`vpngate` is designed to connect remote devices that do not have publicly accessible IP addresses to a shared VPN network.

This provides centralized access to such devices. For example, the VPN server can connect workstations, home computers, friends' computers, MikroTik routers, Wi-Fi access points, and other devices that support VPN client connections.

The server operates in a *road warrior* model: individual clients establish connections to the VPN server independently.

The current version implements the VPN server and includes preliminary components for a Cloak proxy. Only the VPN server is fully implemented.

## 3. Components and features

### 3.1. VPN server

The server supports three connection methods:

| Component | Protocol | Purpose |
|---|---|---|
| IPsec | IKEv2, strongSwan | Client connections over IPsec |
| OpenVPN `strong` | OpenVPN | Connections using stronger cryptographic algorithms |
| OpenVPN `compat` | OpenVPN | Compatibility with clients that have limited OpenVPN support, particularly MikroTik RouterOS v6 |

The OpenVPN `strong`, OpenVPN `compat`, and IPsec components can be disabled using environment variables.

Each VPN client is authenticated using a client certificate. OpenVPN additionally supports username and password authentication.

### 3.2. Internal DNS

A shared DNS zone is maintained for all connected clients. Each client's name is derived from the `CN` field of its certificate.

The following records are registered in DNS when a client successfully connects:

- `A` — client's IPv4 address;
- `AAAA` — client's IPv6 address;
- `PTR` — reverse address lookup.

The client's records are removed when it disconnects.

The DNS server can forward queries that cannot be resolved within the local zone to other DNS servers. The forwarding server addresses are specified using environment variables.

This allows connected devices to communicate with each other using DNS names instead of IP addresses directly.

#### Client certificate CN requirements

Since the `CN` field is used to construct a DNS name, it must comply with the permitted DNS name format.

The following characters are allowed:

- Latin letters `A-Z` and `a-z`;
- digits `0-9`;
- hyphen `-`.

Each DNS label must contain between 1 and 63 characters. A hyphen cannot appear at the beginning or end of a label.

If the `CN` contains invalid characters or otherwise violates DNS naming requirements, DNS registration will fail and the VPN connection will be terminated.

### 3.3. Web interface

The project includes a simple Flask-based web application. A web browser can be used to view the list of connected clients, their connection times, and connection methods.

The displayed data is retrieved from the local DNS zone. In particular, service TXT records contain the client's connection time and connection method encoded in Base64. These records are used by the web application and are not intended for DNS name resolution by network clients.

### 3.4. IPv4 and IPv6 support

Clients can be assigned an IPv6 address in addition to IPv4.

IPv4 is mandatory for OpenVPN: it cannot be disabled while retaining IPv6-only connectivity. IPv4 can be disabled for strongSwan.

IPv6 support is implemented but has not been fully tested.

### 3.5. OpenVPN profiles

OpenVPN provides a profile system that allows different sets of network configuration options and firewall rules to be assigned to clients.

The client submits a username and password along with its certificate. The login contains a username and may also include a profile name. The values are separated by a comma:

```text
username,profile
```

The username must always come first. It is used for additional authentication against the `vpn/ovpn/users.list` file. If a second part is present, it specifies the profile to be assigned to the client.

A profile defines:

- OpenVPN options pushed to the client upon connection, similar to the CCD mechanism;
- firewall rules applied on the server for that client.

For example, the `lan` profile can push routes to one or more private networks to the client. If the client acts as a router, the profile can also include return routes. The server then applies firewall rules allowing traffic exchange with the specified networks.

The `inet` profile can push a default route to the client, allow Internet access, and enable NAT on the server.

This allows clients to select their operating mode by specifying the appropriate profile in their login.

If no profile is specified, no additional profile settings or rules are applied. The client can exchange traffic only with other clients in its own VPN subnet and receives no additional OpenVPN options from the server.

This version does not restrict profile selection based on the client certificate. Any client with a valid certificate, username, and password can request any profile available on the server.

Additionally, individual settings can be assigned to specific clients within a profile based on the `CN` field of their certificates.

## 4. Deployment

The project includes Docker Compose files that allow the container to be deployed using several network modes:

- **`macvlan`** — the container receives its own IP address on an actual VLAN of the local network;
- **standard Docker network** — the container operates within a Docker-managed network;
- **`host`** — the container uses the host's network stack.

The desired mode is selected using the corresponding Compose file.

## 5. Environment variables

Variables defined in the `.env` file are used by the Docker Compose files and, depending on their purpose, passed to the environment of the running container.

The exception is `NET_IP_SERVER_VPN`: it is used only in the Compose file for `macvlan` mode and specifies the VPN server's IP address on the macvlan network.

### 5.1. General settings

| Variable | Example | Description |
|---|---|---|
| `SERVER_VPN_VERSION` | `1` | Tag of the `server_vpn` image used by Compose. The image with this tag is located on the local host or pulled from Docker Hub. |
| `NET_IP_SERVER_VPN` | `172.172.172.4` | IP address of the VPN server on the macvlan network. Used only in the Compose file for `macvlan` mode. |
| `VPN_DNS_ZONE` | `vpn` | Name of the internal DNS zone where connected clients are registered. The web interface is available at `http://vpn` and `http://vpn.vpn`. |
| `PUBLIC_DNS4` | `8.8.8.8` | IPv4 DNS server to which queries that cannot be resolved in the local zone are forwarded. If this variable is empty, such queries are not forwarded and return `NXDOMAIN`. |
| `PUBLIC_DNS6` | — | Equivalent DNS server for IPv6. |

### 5.2. OpenVPN settings

| Variable | Example | Description |
|---|---|---|
| `PUBLIC_STRONG_PORT` | `1194` | TCP port on which the OpenVPN `strong` server listens for incoming connections. |
| `PUBLIC_COMPAT_PORT` | `1195` | TCP port on which the OpenVPN `compat` server listens for incoming connections. |
| `OVPN_STRONG_NET4` | `192.168.10.0/24` | IPv4 address range from which OpenVPN `strong` clients receive their addresses. If this variable is empty, the `strong` server will not start. |
| `OVPN_COMPAT_NET4` | `192.168.11.0/24` | IPv4 address range from which OpenVPN `compat` clients receive their addresses. If this variable is empty, the `strong` server will not start. |
| `OVPN_STRONG_NET6` | `fd7a:c506:d79a:1::/64` | IPv6 address range from which OpenVPN `strong` clients receive their addresses. If this variable is empty, IPv6 is not used in this tunnel. |
| `OVPN_COMPAT_NET6` | `fd7a:c506:d79a:2::/64` | IPv6 address range from which OpenVPN `compat` clients receive their addresses. If this variable is empty, IPv6 is not used in this tunnel. |

### 5.3. IPsec settings

| Variable | Example | Description |
|---|---|---|
| `PUBLIC_DNS_NAME` | `vpn1.example.com` | DNS name used by clients to locate the IPsec server. It must match the name in the server certificate. |
| `SWAN_SERVER_NET4` | `192.168.12.0/24` | IPv4 address range from which strongSwan clients receive their addresses. If this variable is empty, IPv4 is not used in the IPsec tunnel. |
| `SWAN_SERVER_NET6` | `fd7a:c506:d79a:3::/64` | IPv6 address range from which strongSwan clients receive their addresses. If this variable is empty, IPv6 is not used in the IPsec tunnel. |

If both `SWAN_SERVER_NET4` and `SWAN_SERVER_NET6` are empty, strongSwan will not start.

## 6. File structure and data

The directory structure allows flexibility in how Docker images are built, how their backups are stored, and how they are used by the Compose project.

### 6.1. Building Docker images

The `images/` directory contains the files required to build Docker images.

The scripts in this directory allow images to be built manually and copies to be saved in `images_backup/`. This approach is useful, for example, when working in networks with restricted Internet access or when backups need to be managed independently without using Docker Hub. The build scripts can be customized as needed, for example, to add image uploads to Docker Hub.

Manual image building is not required: Docker Compose can use the image directories directly as build contexts.

### 6.2. Certificates and keys: `pki/`

The `pki/` directory is mounted into the container and contains the server certificates and keys required to accept client connections.

The following files are expected:

```text
pki/
├── ca.crt
├── crl.pem
├── server.crt
├── server.key
└── server.tc2
```

`server.tc2` is the server-side `tls-crypt-v2` key used by the OpenVPN `strong` configuration. This key is not required when running only the OpenVPN `compat` configuration.

### 6.3. OpenVPN status files: `stat/`

The `stat/` directory is mounted into the container. OpenVPN servers store their status files in this directory:

```text
server-strong.status
server-compat.status
```

### 6.4. OpenVPN configuration: `vpn/`

The `vpn/` directory is mounted into the container and contains profile settings shared by both OpenVPN servers.

Directory structure:

```text
vpn/
└── ovpn/
    ├── users.list
    └── profiles/
        ├── lan/
        │   ├── DEFAULT.conf
        │   ├── DEFAULT.fwl
        │   ├── client1.conf
        │   └── client1.fwl
        └── inet/
            ├── DEFAULT.conf
            └── DEFAULT.fwl
```

The `lan` and `inet` directory names are provided as examples.

The `vpn/` directory is read whenever a client connects. Therefore, profile settings can be modified externally without rebuilding the image or restarting the container.

## 7. OpenVPN authentication and profiles

### 7.1. User list: `vpn/ovpn/users.list`

The `vpn/ovpn/users.list` file contains the usernames and passwords used for additional OpenVPN client authentication.

Each line contains two fields separated by whitespace:

```text
<username> <password>
```

The first field is the username; the second is the password.

Leading and trailing whitespace, as well as whitespace between fields, is trimmed when the file is processed. Lines beginning with `#` are treated as comments.

Either field can be `*`, which matches any value.

For example:

```text
* *
```

This entry allows any username and password. It can be used when profiles need to be assigned but additional username and password verification is not required.

When using profiles, the client submits a login in the following format:

```text
username,profile
```

The first part of the login, `username`, is used for authentication against `vpn/ovpn/users.list`. The second part specifies the OpenVPN profile.

### 7.2. Profile directory

The `vpn/ovpn/profiles/` directory contains subdirectories with the settings for individual profiles. Each subdirectory is named after the profile specified in the client's login.

Each profile contains two types of files:

- `.conf` — OpenVPN options pushed to the client;
- `.fwl` — firewall rules applied on the server.

File names correspond to the `CN` field of the client certificate.

Each profile can contain client-specific files as well as default configuration files:

```text
profiles/
└── <profile>/
    ├── DEFAULT.conf
    ├── DEFAULT.fwl
    ├── <client-CN>.conf
    └── <client-CN>.fwl
```

Client-specific files are selected independently:

- If the client-specific `.conf` file is missing, `DEFAULT.conf` is used.
- If the client-specific `.fwl` file is missing, `DEFAULT.fwl` is used.

This allows a client to have only one client-specific file, with the other file taken from the default configuration.

If neither the client-specific file nor the corresponding `DEFAULT` file exists for either file type, the client will be disconnected.

Both file types support comments: lines beginning with `#`.

### 7.3. `.conf` files: OpenVPN configuration

`.conf` files contain OpenVPN directives similar to those used in CCD. Template variable substitution is also supported.

This allows the same profile file to be used by both OpenVPN servers, even when their addresses and DNS parameters differ.

For example:

```text
push "dhcp-option DOMAIN {{VPN_DOMAIN}}"
push "dhcp-option DNS {{VPN_SERVER_IP4}}"
push "dhcp-option DNS {{VPN_SERVER_IP6}}"
```

Supported variables:

| Variable | Description |
|---|---|
| `VPN_DOMAIN` | Name of the internal DNS zone in which clients are registered. |
| `VPN_SERVER_IP4` | IPv4 address of the server in the tunnel. |
| `VPN_SERVER_IP6` | IPv6 address of the server in the tunnel. |

### 7.4. `.fwl` files: firewall rules

`.fwl` files contain simplified directives used to generate firewall rules on the server.

For example, the `lan` profile may need to allow a client to access an additional private network:

```text
ALLOWNET 192.168.2.0/24
```

The `inet` profile can use the following set of rules:

```text
NAT
ALLOWNET inet
```

This enables masquerading for the client's outgoing traffic and allows traffic exchange with all IPv4 and IPv6 addresses.

Supported directives:

| Directive | Description |
|---|---|
| `NAT` | Masquerade all traffic originating from the client. |
| `NAT4` | Masquerade IPv4 traffic only. |
| `NAT6` | Masquerade IPv6 traffic only. |
| `ALLOWNET NET` | Allow bidirectional traffic between the client and the specified network `NET`. |

`NET` can be specified as an address range in `net/len` notation (IPv4 or IPv6), or as the special value `inet`, which represents the entire address space of both families: `0.0.0.0/0` and `::/0`.
