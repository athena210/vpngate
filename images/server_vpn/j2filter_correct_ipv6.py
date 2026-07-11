#!/usr/bin/env python3

import ipaddress

def iplib_first_addr(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    new_addr = None
    i = 1
    if (addr.version == 6 or (addr.version == 4 and net.num_addresses <= 2)):
        i = 0
    try:
        new_addr = net[i]
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return str(new_addr.exploded if new_addr is not None else new_addr )


def iplib_second_addr(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    new_addr = None
    i = 2
    if (addr.version == 6 or (addr.version == 4 and net.num_addresses <= 2)):
        i = 1
    try:
        new_addr = net[i]
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return str(new_addr.exploded if new_addr is not None else new_addr )


def iplib_last_addr(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    new_addr = None
    i = -1
    if (addr.version == 4 and net.num_addresses > 2):
        i = -2
    try:
        new_addr = net[i]
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return str(new_addr.exploded if new_addr is not None else new_addr )


def iplib_last_minus_dhcp_block_addr(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network

    net_block_size = net.num_addresses
    if (
        (addr.version == 4 and net_block_size < 5) or
        (addr.version == 6 and net_block_size < 3)
    ):
        return str(None)

    new_addr = None
    dhcp_max_size = 1 << 31
    new_addr_idx = 0
    if addr.version == 4:
        dhcp_block_size = min(dhcp_max_size, net_block_size - 3)
        new_addr_idx -= dhcp_block_size + 1
    else:
        dhcp_block_size = min(dhcp_max_size, net_block_size - 1)
        new_addr_idx -= dhcp_block_size

    new_addr = None
    try:
        new_addr = net[new_addr_idx]
    # trunk-ignore(bandit/B110)
    except Exception:
        pass

    return str(new_addr.exploded if new_addr is not None else new_addr )


def iplib_first_addr_with_netlen(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    first_addr = next(iter(net.hosts()), None)
    if first_addr:
        first_addr = first_addr.exploded
    return f"{first_addr}/{net.prefixlen}"


def iplib_ptr(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network

    if addr.version == 4:
        new_len = (net.prefixlen // 8) * 8
        if new_len == 0:
            return "in-addr.arpa"
        new_net = ipaddress.ip_network(f"{net.network_address}/{new_len}", strict=False)
        octets = str(new_net.network_address).split(".")
        zone_parts = octets[:new_len // 8][::-1]
        return ".".join(zone_parts) + ".in-addr.arpa"
    else:
        new_len = (net.prefixlen // 4) * 4
        if new_len == 0:
            return "ip6.arpa"
        new_net = ipaddress.ip_network(f"{net.network_address}/{new_len}", strict=False)
        hex_str = new_net.network_address.exploded.replace(":", "")
        nibbles = new_len // 4
        zone_parts = list(hex_str[:nibbles])[::-1]
        return ".".join(zone_parts) + ".ip6.arpa"


def iplib_network(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    return str(net.network_address.exploded)


def iplib_netlen(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    return str(net.prefixlen)


def iplib_netmask(cidr: str) -> str:
    addr = ipaddress.ip_interface(cidr)
    net = addr.network
    return str(net.netmask.exploded)
